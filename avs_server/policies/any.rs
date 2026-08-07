// Copyright 2026 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

use avs_proto_rust::avs::Policy;

use oak_proto_rust::oak::attestation::v1::{
    binary_reference_value, kernel_binary_reference_value, mpm_reference_value, reference_values,
    BinaryReferenceValue, KernelBinaryReferenceValue, MpmReferenceValue, TLogReferenceValues,
};

/// Helper to extract a mutable reference to the `TLogReferenceValues` from an
/// optional `BinaryReferenceValue`.
#[allow(dead_code)]
fn get_tlog_from_binary_reference_value(
    binary: &mut Option<BinaryReferenceValue>,
) -> Option<&mut TLogReferenceValues> {
    let binary = binary.as_mut()?;
    let binary_reference_value::Type::Endorsement(endorsement) = binary.r#type.as_mut()? else {
        return None;
    };
    endorsement.tlog.as_mut()
}

/// Helper to extract a mutable reference to the `TLogReferenceValues` from an
/// optional `KernelBinaryReferenceValue`.
#[allow(dead_code)]
fn get_tlog_from_kernel_binary_reference_value(
    kernel: &mut Option<KernelBinaryReferenceValue>,
) -> Option<&mut TLogReferenceValues> {
    let kernel = kernel.as_mut()?;
    let kernel_binary_reference_value::Type::Endorsement(endorsement) = kernel.r#type.as_mut()?
    else {
        return None;
    };
    endorsement.tlog.as_mut()
}

/// Helper to extract a mutable reference to the `TLogReferenceValues` from an
/// optional `MpmReferenceValue`.
fn get_tlog_from_mpm_reference_value(
    mpm: &mut Option<MpmReferenceValue>,
) -> Option<&mut TLogReferenceValues> {
    let mpm = mpm.as_mut()?;
    let mpm_reference_value::Type::Endorsement(endorsement) = mpm.r#type.as_mut()? else {
        return None;
    };
    endorsement.tlog.as_mut()
}

/// Returns a list of mutable references to all present `TLogReferenceValues`
/// fields in the given `Policy`.
#[allow(dead_code, deprecated)]
fn get_tlog_fields(policy: &mut Policy) -> Vec<&mut TLogReferenceValues> {
    let mut tlog_fields = Vec::new();

    let Some(ref mut oak_ref_values) = policy.oak_reference_values else {
        return tlog_fields;
    };

    let Some(reference_values::Type::Cbt(ref mut cbt_reference_values)) = oak_ref_values.r#type
    else {
        return tlog_fields;
    };

    // root_layer -> amd_sev -> stage0
    tlog_fields.extend(
        cbt_reference_values
            .root_layer
            .as_mut()
            .and_then(|r| r.amd_sev.as_mut())
            .and_then(|a| get_tlog_from_binary_reference_value(&mut a.stage0)),
    );

    // kernel_layer -> kernel & init_ram_fs
    if let Some(ref mut k) = cbt_reference_values.kernel_layer {
        tlog_fields.extend(get_tlog_from_kernel_binary_reference_value(&mut k.kernel));
        tlog_fields.extend(get_tlog_from_binary_reference_value(&mut k.init_ram_fs));
    }

    // layer1 -> runtime_agent_binary & userspace
    if let Some(ref mut l1) = cbt_reference_values.layer1 {
        tlog_fields.extend(get_tlog_from_binary_reference_value(&mut l1.runtime_agent_binary));
        tlog_fields.extend(get_tlog_from_binary_reference_value(&mut l1.userspace));
    }

    // layer2 -> binary_mpm
    tlog_fields.extend(
        cbt_reference_values
            .layer2
            .as_mut()
            .and_then(|l2| get_tlog_from_mpm_reference_value(&mut l2.binary_mpm)),
    );

    tlog_fields
}

/// Unconditionally sets the `any` strategy on every `TLogReferenceValues` in
/// the policy, overwriting any previously-set strategy (e.g. `all`).
#[allow(dead_code)]
pub fn override_with_any_strategy(policy: &mut Policy) -> anyhow::Result<()> {
    use oak_proto_rust::oak::attestation::v1::t_log_reference_values;

    for tlog_field in get_tlog_fields(policy) {
        tlog_field.strategy = Some(t_log_reference_values::Strategy::Any(()));
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    // --- Mock Helpers ---

    fn mock_binary_ref_value() -> BinaryReferenceValue {
        use oak_proto_rust::oak::attestation::v1::{
            EndorsementReferenceValue, TLogReferenceValues,
        };
        BinaryReferenceValue {
            r#type: Some(binary_reference_value::Type::Endorsement(EndorsementReferenceValue {
                tlog: Some(TLogReferenceValues::default()),
                ..Default::default()
            })),
        }
    }

    fn mock_kernel_binary_ref_value() -> KernelBinaryReferenceValue {
        use oak_proto_rust::oak::attestation::v1::{
            EndorsementReferenceValue, TLogReferenceValues,
        };
        KernelBinaryReferenceValue {
            r#type: Some(kernel_binary_reference_value::Type::Endorsement(
                EndorsementReferenceValue {
                    tlog: Some(TLogReferenceValues::default()),
                    ..Default::default()
                },
            )),
        }
    }

    fn mock_mpm_ref_value() -> MpmReferenceValue {
        use oak_proto_rust::oak::attestation::v1::{
            EndorsementReferenceValue, TLogReferenceValues,
        };
        MpmReferenceValue {
            r#type: Some(mpm_reference_value::Type::Endorsement(EndorsementReferenceValue {
                tlog: Some(TLogReferenceValues::default()),
                ..Default::default()
            })),
        }
    }

    #[test]
    fn test_get_tlog_fields_empty() {
        let mut policy = Policy::default();
        let fields = get_tlog_fields(&mut policy);
        assert!(fields.is_empty());
    }

    #[test]
    #[allow(deprecated)]
    fn test_get_tlog_fields_extracts_all_layers() {
        use oak_proto_rust::oak::attestation::v1::{
            AmdSevReferenceValues, CbLayer1TransparentReferenceValues,
            CbLayer2TransparentReferenceValues, CbTransparentReferenceValues,
            KernelLayerReferenceValues, ReferenceValues, RootLayerReferenceValues,
        };

        let mut policy = Policy {
            oak_reference_values: Some(ReferenceValues {
                r#type: Some(reference_values::Type::Cbt(CbTransparentReferenceValues {
                    root_layer: Some(RootLayerReferenceValues {
                        amd_sev: Some(AmdSevReferenceValues {
                            stage0: Some(mock_binary_ref_value()),
                            ..Default::default()
                        }),
                        ..Default::default()
                    }),
                    kernel_layer: Some(KernelLayerReferenceValues {
                        kernel: Some(mock_kernel_binary_ref_value()),
                        init_ram_fs: Some(mock_binary_ref_value()),
                        ..Default::default()
                    }),
                    layer1: Some(CbLayer1TransparentReferenceValues {
                        runtime_agent_binary: Some(mock_binary_ref_value()),
                        userspace: Some(mock_binary_ref_value()),
                        ..Default::default()
                    }),
                    layer2: Some(CbLayer2TransparentReferenceValues {
                        #[allow(deprecated)]
                        binary_mpm: Some(mock_mpm_ref_value()),
                        binary_mpms: vec![mock_mpm_ref_value(), mock_mpm_ref_value()],
                    }),
                })),
            }),
            ..Default::default()
        };

        let fields = get_tlog_fields(&mut policy);
        assert_eq!(fields.len(), 6);
    }

    #[test]
    #[allow(deprecated)]
    fn test_get_tlog_fields_partially_populated() {
        use oak_proto_rust::oak::attestation::v1::{
            CbLayer2TransparentReferenceValues, CbTransparentReferenceValues,
            KernelLayerReferenceValues, ReferenceValues,
        };

        let mut policy = Policy {
            oak_reference_values: Some(ReferenceValues {
                r#type: Some(reference_values::Type::Cbt(CbTransparentReferenceValues {
                    root_layer: None,
                    kernel_layer: Some(KernelLayerReferenceValues {
                        kernel: Some(mock_kernel_binary_ref_value()),
                        init_ram_fs: None,
                        ..Default::default()
                    }),
                    layer1: None,
                    layer2: Some(CbLayer2TransparentReferenceValues {
                        #[allow(deprecated)]
                        binary_mpm: Some(mock_mpm_ref_value()),
                        binary_mpms: vec![],
                    }),
                })),
            }),
            ..Default::default()
        };

        let fields = get_tlog_fields(&mut policy);
        assert_eq!(fields.len(), 2);
    }

    #[test]
    fn test_override_with_any_strategy_sets_any() {
        use oak_proto_rust::oak::attestation::v1::{
            t_log_reference_values, AmdSevReferenceValues, CbTransparentReferenceValues,
            ReferenceValues, RootLayerReferenceValues,
        };

        let mut policy = Policy {
            oak_reference_values: Some(ReferenceValues {
                r#type: Some(reference_values::Type::Cbt(CbTransparentReferenceValues {
                    root_layer: Some(RootLayerReferenceValues {
                        amd_sev: Some(AmdSevReferenceValues {
                            stage0: Some(mock_binary_ref_value()),
                            ..Default::default()
                        }),
                        ..Default::default()
                    }),
                    ..Default::default()
                })),
            }),
            ..Default::default()
        };

        override_with_any_strategy(&mut policy).expect("failed to inject any strategy");

        // Verify the strategy was set to `any`
        let tlog_fields = get_tlog_fields(&mut policy);
        assert_eq!(tlog_fields.len(), 1);
        assert_eq!(tlog_fields[0].strategy, Some(t_log_reference_values::Strategy::Any(())));
    }

    #[test]
    fn test_override_with_any_strategy_overwrites_existing() {
        use oak_proto_rust::oak::attestation::v1::{
            t_log_reference_values, AmdSevReferenceValues, BinaryReferenceValue,
            CbTransparentReferenceValues, EndorsementReferenceValue, ReferenceValues,
            RootLayerReferenceValues, TLogReferenceValues,
        };

        // Create a policy where the strategy is already set to `all`.
        let mut policy = Policy {
            oak_reference_values: Some(ReferenceValues {
                r#type: Some(reference_values::Type::Cbt(CbTransparentReferenceValues {
                    root_layer: Some(RootLayerReferenceValues {
                        amd_sev: Some(AmdSevReferenceValues {
                            stage0: Some(BinaryReferenceValue {
                                r#type: Some(binary_reference_value::Type::Endorsement(
                                    EndorsementReferenceValue {
                                        tlog: Some(TLogReferenceValues {
                                            strategy: Some(t_log_reference_values::Strategy::All(
                                                (),
                                            )),
                                            ..Default::default()
                                        }),
                                        ..Default::default()
                                    },
                                )),
                            }),
                            ..Default::default()
                        }),
                        ..Default::default()
                    }),
                    ..Default::default()
                })),
            }),
            ..Default::default()
        };

        override_with_any_strategy(&mut policy).expect("failed to inject any strategy");

        // Verify the pre-existing `all` strategy was replaced with `any`.
        let tlog_fields = get_tlog_fields(&mut policy);
        assert_eq!(tlog_fields.len(), 1);
        assert_eq!(tlog_fields[0].strategy, Some(t_log_reference_values::Strategy::Any(())));
    }
}
