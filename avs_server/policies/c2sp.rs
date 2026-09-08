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
    binary_reference_value, kernel_binary_reference_value, mpm_reference_value,
    BinaryReferenceValue, C2sptLogProofReferenceValue, KernelBinaryReferenceValue,
    MpmReferenceValue,
};

/// The embedded C2SP tlog-policy file.
pub(crate) const PROD_VERIFIER_POLICY: &str = include_str!("prod-verifier.policy");

/// Helper to extract a mutable reference to the `c2sp` field from an optional
/// `BinaryReferenceValue`.
#[allow(dead_code)]
fn get_c2sp_from_binary_reference_value(
    binary: &mut Option<BinaryReferenceValue>,
) -> Option<&mut C2sptLogProofReferenceValue> {
    let binary = binary.as_mut()?;
    let binary_reference_value::Type::Endorsement(endorsement) = binary.r#type.as_mut()? else {
        return None;
    };
    endorsement.tlog.as_mut()?.c2sp.as_mut()
}

/// Helper to extract a mutable reference to the `c2sp` field from an optional
/// `KernelBinaryReferenceValue`.
#[allow(dead_code)]
fn get_c2sp_from_kernel_binary_reference_value(
    kernel: &mut Option<KernelBinaryReferenceValue>,
) -> Option<&mut C2sptLogProofReferenceValue> {
    let kernel = kernel.as_mut()?;
    let kernel_binary_reference_value::Type::Endorsement(endorsement) = kernel.r#type.as_mut()?
    else {
        return None;
    };
    endorsement.tlog.as_mut()?.c2sp.as_mut()
}

/// Helper to extract a mutable reference to the `c2sp` field from a
/// `MpmReferenceValue`.
#[allow(dead_code)]
fn get_c2sp_from_single_mpm_reference_value(
    mpm: &mut MpmReferenceValue,
) -> Option<&mut C2sptLogProofReferenceValue> {
    let mpm_reference_value::Type::Endorsement(endorsement) = mpm.r#type.as_mut()? else {
        return None;
    };
    endorsement.tlog.as_mut()?.c2sp.as_mut()
}

/// Helper to extract a mutable reference to the `c2sp` field from an optional
/// `MpmReferenceValue`.
#[allow(dead_code)]
fn get_c2sp_from_mpm_reference_value(
    mpm: &mut Option<MpmReferenceValue>,
) -> Option<&mut C2sptLogProofReferenceValue> {
    get_c2sp_from_single_mpm_reference_value(mpm.as_mut()?)
}

/// Returns a list of mutable references to all present `c2sp` fields in the
/// given `Policy`.
#[allow(dead_code, deprecated)]
fn get_c2sp_fields(policy: &mut Policy) -> Vec<&mut C2sptLogProofReferenceValue> {
    use oak_proto_rust::oak::attestation::v1::reference_values;

    let mut c2sp_fields = Vec::new();

    let Some(ref mut oak_ref_values) = policy.oak_reference_values else {
        return c2sp_fields;
    };

    let Some(reference_values::Type::Cbt(ref mut cbt_reference_values)) = oak_ref_values.r#type
    else {
        return c2sp_fields;
    };

    // root_layer -> amd_sev -> stage0
    c2sp_fields.extend(
        cbt_reference_values
            .root_layer
            .as_mut()
            .and_then(|r| r.amd_sev.as_mut())
            .and_then(|a| get_c2sp_from_binary_reference_value(&mut a.stage0)),
    );

    // kernel_layer -> kernel & init_ram_fs
    if let Some(ref mut k) = cbt_reference_values.kernel_layer {
        c2sp_fields.extend(get_c2sp_from_kernel_binary_reference_value(&mut k.kernel));
        c2sp_fields.extend(get_c2sp_from_binary_reference_value(&mut k.init_ram_fs));
    }

    // layer1 -> runtime_agent_binary & userspace
    if let Some(ref mut l1) = cbt_reference_values.layer1 {
        c2sp_fields.extend(get_c2sp_from_binary_reference_value(&mut l1.runtime_agent_binary));
        c2sp_fields.extend(get_c2sp_from_binary_reference_value(&mut l1.userspace));
    }

    // layer2 -> binary_mpm & binary_mpms
    if let Some(ref mut l2) = cbt_reference_values.layer2 {
        c2sp_fields.extend(get_c2sp_from_mpm_reference_value(&mut l2.binary_mpm));
        for mpm in &mut l2.binary_mpms {
            c2sp_fields.extend(get_c2sp_from_single_mpm_reference_value(mpm));
        }
    }

    c2sp_fields
}

/// Injects `c2sp_policy` into all `c2sp` fields in the policy.
#[allow(dead_code)]
pub fn inject_c2sp_policy(policy: &mut Policy, c2sp_policy: &str) -> anyhow::Result<()> {
    for c2sp_field in get_c2sp_fields(policy) {
        c2sp_field.policy = c2sp_policy.to_string();
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use oak_proto_rust::oak::attestation::v1::reference_values;

    /// Stand-in policy text. `inject_c2sp_policy` stores the string verbatim,
    /// so its content is irrelevant to these tests.
    const TEST_C2SP_POLICY: &str = "test c2sp policy";

    // --- Mock Helpers for get_c2sp_fields Tests ---

    fn mock_binary_ref_value() -> BinaryReferenceValue {
        use oak_proto_rust::oak::attestation::v1::{
            EndorsementReferenceValue, TLogReferenceValues,
        };
        BinaryReferenceValue {
            r#type: Some(binary_reference_value::Type::Endorsement(EndorsementReferenceValue {
                tlog: Some(TLogReferenceValues {
                    c2sp: Some(C2sptLogProofReferenceValue::default()),
                    ..Default::default()
                }),
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
                    tlog: Some(TLogReferenceValues {
                        c2sp: Some(C2sptLogProofReferenceValue::default()),
                        ..Default::default()
                    }),
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
                tlog: Some(TLogReferenceValues {
                    c2sp: Some(C2sptLogProofReferenceValue::default()),
                    ..Default::default()
                }),
                ..Default::default()
            })),
        }
    }

    #[test]
    fn test_get_c2sp_fields_empty() {
        let mut policy = Policy::default();
        let fields = get_c2sp_fields(&mut policy);
        assert!(fields.is_empty());
    }

    #[test]
    #[allow(deprecated)]
    fn test_get_c2sp_fields_extracts_all_layers() {
        use oak_proto_rust::oak::attestation::v1::{
            AmdSevReferenceValues, CbLayer1TransparentReferenceValues,
            CbLayer2TransparentReferenceValues, CbTransparentReferenceValues,
            KernelLayerReferenceValues, ReferenceValues, RootLayerReferenceValues,
        };

        // 1. Construct a Policy where all 6 possible C2SP locations are
        //    populated
        let mut policy = Policy {
            oak_reference_values: Some(ReferenceValues {
                r#type: Some(reference_values::Type::Cbt(CbTransparentReferenceValues {
                    // Root Layer
                    root_layer: Some(RootLayerReferenceValues {
                        amd_sev: Some(AmdSevReferenceValues {
                            stage0: Some(mock_binary_ref_value()),
                            ..Default::default()
                        }),
                        ..Default::default()
                    }),
                    // Kernel Layer
                    kernel_layer: Some(KernelLayerReferenceValues {
                        kernel: Some(mock_kernel_binary_ref_value()),
                        init_ram_fs: Some(mock_binary_ref_value()),
                        ..Default::default()
                    }),
                    // Layer 1
                    layer1: Some(CbLayer1TransparentReferenceValues {
                        runtime_agent_binary: Some(mock_binary_ref_value()),
                        userspace: Some(mock_binary_ref_value()),
                        ..Default::default()
                    }),
                    // Layer 2
                    layer2: Some(CbLayer2TransparentReferenceValues {
                        #[allow(deprecated)]
                        binary_mpm: Some(mock_mpm_ref_value()),
                        binary_mpms: vec![mock_mpm_ref_value(), mock_mpm_ref_value()],
                    }),
                })),
            }),
            ..Default::default()
        };

        // 2. Invoke get_c2sp_fields
        let fields = get_c2sp_fields(&mut policy);

        // 3. Assert all 8 fields across the 4 layers were extracted: 1 (stage0)
        //    + 2 (kernel, init_ram_fs) + 2 (runtime_agent_binary, userspace)
        //    + 1 (binary_mpm) + 2 (binary_mpms) = 8
        assert_eq!(fields.len(), 8);
    }

    #[test]
    #[allow(deprecated)]
    fn test_get_c2sp_fields_partially_populated() {
        use oak_proto_rust::oak::attestation::v1::{
            CbLayer2TransparentReferenceValues, CbTransparentReferenceValues,
            KernelLayerReferenceValues, ReferenceValues,
        };

        // 1. Construct a Policy where only some layers and fields are
        //    populated:
        //    - root_layer is None
        //    - kernel_layer: kernel is Some, init_ram_fs is None
        //    - layer1 is None
        //    - layer2 is Some
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
                        binary_mpms: vec![mock_mpm_ref_value()],
                    }),
                })),
            }),
            ..Default::default()
        };

        // 2. Invoke get_c2sp_fields
        let fields = get_c2sp_fields(&mut policy);

        // 3. Assert exactly 3 fields extracted: 1 (kernel) + 1 (binary_mpm) + 1
        //    (binary_mpms)
        assert_eq!(fields.len(), 3);
    }

    #[test]
    fn test_inject_c2sp_policy_success() {
        use oak_proto_rust::oak::attestation::v1::{
            AmdSevReferenceValues, BinaryReferenceValue, CbTransparentReferenceValues,
            EndorsementReferenceValue, ReferenceValues, RootLayerReferenceValues,
            TLogReferenceValues,
        };

        // 1. Construct the initial Policy with one of the layers populated
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

        // 2. Invoke the public API
        inject_c2sp_policy(&mut policy, TEST_C2SP_POLICY).expect("failed to inject c2sp policy");

        // 3. Construct the expected Policy object (with the c2sp policy
        //    injected)
        let expected_policy = Policy {
            oak_reference_values: Some(ReferenceValues {
                r#type: Some(reference_values::Type::Cbt(CbTransparentReferenceValues {
                    root_layer: Some(RootLayerReferenceValues {
                        amd_sev: Some(AmdSevReferenceValues {
                            stage0: Some(BinaryReferenceValue {
                                r#type: Some(binary_reference_value::Type::Endorsement(
                                    EndorsementReferenceValue {
                                        tlog: Some(TLogReferenceValues {
                                            c2sp: Some(C2sptLogProofReferenceValue {
                                                policy: TEST_C2SP_POLICY.to_string(),
                                            }),
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

        // 4. Assert that the mutated policy matches the expected policy exactly
        assert_eq!(policy, expected_policy);
    }

    #[test]
    fn test_inject_c2sp_policy_no_c2sp_fields() {
        use oak_proto_rust::oak::attestation::v1::{
            AmdSevReferenceValues, CbTransparentReferenceValues, ReferenceValues,
            RootLayerReferenceValues,
        };

        // Construct a policy with skip {} (no tlog, hence no c2sp)
        let mut policy = Policy {
            oak_reference_values: Some(ReferenceValues {
                r#type: Some(reference_values::Type::Cbt(CbTransparentReferenceValues {
                    root_layer: Some(RootLayerReferenceValues {
                        amd_sev: Some(AmdSevReferenceValues { ..Default::default() }),
                        ..Default::default()
                    }),
                    ..Default::default()
                })),
            }),
            ..Default::default()
        };

        let initial_policy = policy.clone();

        // Invoke the public API
        inject_c2sp_policy(&mut policy, TEST_C2SP_POLICY).expect("failed to inject c2sp policy");

        // Assert that the policy was not modified at all
        assert_eq!(policy, initial_policy);
    }
}
