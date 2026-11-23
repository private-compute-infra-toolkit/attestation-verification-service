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

use std::time::SystemTime;

use avs_proto_rust::avs::Policy;

use crate::certs::extract_spki_from_pem;
#[cfg(not(test))]
use crate::certs::load_certificates;

use oak_proto_rust::oak::attestation::v1::{
    binary_reference_value, kernel_binary_reference_value, mpm_reference_value, reference_values,
    BinaryReferenceValue, CbTransparentReferenceValues, KernelBinaryReferenceValue, KeyType,
    MpmReferenceValue, OakContainersReferenceValues, PesReferenceValue, VerifyingKey,
    VerifyingKeySet,
};

/// Loads a single `VerifyingKeySet` from the certificates valid at `now`.
fn load_rsa_sha2_256_keyset(
    certs: &[String],
    now: SystemTime,
) -> anyhow::Result<Option<VerifyingKeySet>> {
    if certs.is_empty() {
        return Ok(None);
    }

    let mut keys = Vec::new();
    for pem_content in certs {
        for raw_key in extract_spki_from_pem(pem_content, now)? {
            keys.push(VerifyingKey {
                r#type: KeyType::RsaSha2256 as i32,
                raw: raw_key,
                // key_id is not set because pes_endorsement does not define it
                ..Default::default()
            });
        }
    }

    Ok(Some(VerifyingKeySet { keys, signed_timestamp: None }))
}

/// Helper to extract a mutable reference to the `pes` field from an optional
/// `BinaryReferenceValue`.
fn get_pes_from_binary_reference_value(
    binary: &mut Option<BinaryReferenceValue>,
) -> Option<&mut PesReferenceValue> {
    let binary = binary.as_mut()?;
    let binary_reference_value::Type::Endorsement(endorsement) = binary.r#type.as_mut()? else {
        return None;
    };
    endorsement.tlog.as_mut()?.pes.as_mut()
}

/// Helper to extract a mutable reference to the `pes` field from an optional
/// `KernelBinaryReferenceValue`.
fn get_pes_from_kernel_binary_reference_value(
    kernel: &mut Option<KernelBinaryReferenceValue>,
) -> Option<&mut PesReferenceValue> {
    let kernel = kernel.as_mut()?;
    let kernel_binary_reference_value::Type::Endorsement(endorsement) = kernel.r#type.as_mut()?
    else {
        return None;
    };
    endorsement.tlog.as_mut()?.pes.as_mut()
}

/// Helper to extract a mutable reference to the `pes` field from a
/// `MpmReferenceValue`.
fn get_pes_from_single_mpm_reference_value(
    mpm: &mut MpmReferenceValue,
) -> Option<&mut PesReferenceValue> {
    let mpm_reference_value::Type::Endorsement(endorsement) = mpm.r#type.as_mut()? else {
        return None;
    };
    endorsement.tlog.as_mut()?.pes.as_mut()
}

/// Helper to extract a mutable reference to the `pes` field from an optional
/// `MpmReferenceValue`.
fn get_pes_from_mpm_reference_value(
    mpm: &mut Option<MpmReferenceValue>,
) -> Option<&mut PesReferenceValue> {
    get_pes_from_single_mpm_reference_value(mpm.as_mut()?)
}

/// Returns a list of mutable references to all present `pes` fields in the
/// given `CbTransparentReferenceValues`.
#[allow(deprecated)]
fn get_pes_fields_from_cbt(
    cbt_reference_values: &mut CbTransparentReferenceValues,
) -> Vec<&mut PesReferenceValue> {
    let mut pes_fields = Vec::new();

    // root_layer -> amd_sev -> stage0
    pes_fields.extend(
        cbt_reference_values
            .root_layer
            .as_mut()
            .and_then(|r| r.amd_sev.as_mut())
            .and_then(|a| get_pes_from_binary_reference_value(&mut a.stage0)),
    );

    // kernel_layer -> kernel & init_ram_fs
    if let Some(ref mut k) = cbt_reference_values.kernel_layer {
        pes_fields.extend(get_pes_from_kernel_binary_reference_value(&mut k.kernel));
        pes_fields.extend(get_pes_from_binary_reference_value(&mut k.init_ram_fs));
    }

    // layer1 -> runtime_agent, runtime_agent_binary & userspace
    if let Some(ref mut l1) = cbt_reference_values.layer1 {
        pes_fields.extend(get_pes_from_binary_reference_value(&mut l1.runtime_agent));
        pes_fields.extend(get_pes_from_binary_reference_value(&mut l1.runtime_agent_binary));
        pes_fields.extend(get_pes_from_binary_reference_value(&mut l1.userspace));
    }

    // layer2 -> binary_mpm & binary_mpms
    if let Some(ref mut l2) = cbt_reference_values.layer2 {
        pes_fields.extend(get_pes_from_mpm_reference_value(&mut l2.binary_mpm));
        for mpm in &mut l2.binary_mpms {
            pes_fields.extend(get_pes_from_single_mpm_reference_value(mpm));
        }
    }

    pes_fields
}

/// Returns a list of mutable references to all present `pes` fields in the
/// given `OakContainersReferenceValues`.
fn get_pes_fields_from_oak_containers(
    oc_reference_values: &mut OakContainersReferenceValues,
) -> Vec<&mut PesReferenceValue> {
    let mut pes_fields = Vec::new();

    // root_layer -> amd_sev.stage0 & intel_tdx.stage0
    if let Some(ref mut r) = oc_reference_values.root_layer {
        if let Some(ref mut a) = r.amd_sev {
            pes_fields.extend(get_pes_from_binary_reference_value(&mut a.stage0));
        }
        if let Some(ref mut t) = r.intel_tdx {
            pes_fields.extend(get_pes_from_binary_reference_value(&mut t.stage0));
        }
    }

    // kernel_layer -> kernel & init_ram_fs
    if let Some(ref mut k) = oc_reference_values.kernel_layer {
        pes_fields.extend(get_pes_from_kernel_binary_reference_value(&mut k.kernel));
        pes_fields.extend(get_pes_from_binary_reference_value(&mut k.init_ram_fs));
    }

    // system_layer -> system_image
    if let Some(ref mut s) = oc_reference_values.system_layer {
        pes_fields.extend(get_pes_from_binary_reference_value(&mut s.system_image));
    }

    // container_layer -> binary & configuration
    if let Some(ref mut c) = oc_reference_values.container_layer {
        pes_fields.extend(get_pes_from_binary_reference_value(&mut c.binary));
        pes_fields.extend(get_pes_from_binary_reference_value(&mut c.configuration));
    }

    pes_fields
}

/// Returns a list of mutable references to all present `pes` fields in the
/// given `Policy`.
fn get_pes_fields(policy: &mut Policy) -> Vec<&mut PesReferenceValue> {
    let oak_reference_values = &mut policy.oak_reference_values;
    let shadow = &mut policy.shadow;

    let mut fields = match oak_reference_values.as_mut().and_then(|rv| rv.r#type.as_mut()) {
        Some(reference_values::Type::Cbt(cbt_reference_values)) => {
            get_pes_fields_from_cbt(cbt_reference_values)
        }
        Some(reference_values::Type::OakContainers(oc_reference_values)) => {
            get_pes_fields_from_oak_containers(oc_reference_values)
        }
        _ => Vec::new(),
    };

    // The shadow layer-2 candidate is verified with the same t-log checks as
    // the main reference values, so it needs the same injected values.
    if let Some(layer2) = shadow.as_mut().and_then(|s| s.layer2.as_mut()) {
        for mpm in &mut layer2.binary_mpms {
            fields.extend(get_pes_from_single_mpm_reference_value(mpm));
        }
    }

    fields
}

/// Loads the PES verifying keys valid at `now` from the glob pattern and
/// injects them into the retrieved `pes` fields in the policy.
pub fn inject_pes_keys(policy: &mut Policy, now: SystemTime) -> anyhow::Result<()> {
    let glob_pattern = "etc/pes-certs/**/*.pem";
    let certs = load_certificates(glob_pattern)?;

    if let Some(key_set) = load_rsa_sha2_256_keyset(&certs, now)? {
        for pes_field in get_pes_fields(policy) {
            pes_field.key_set = Some(key_set.clone());
        }
    }

    Ok(())
}

#[cfg(test)]
mod mocks {
    use std::cell::RefCell;

    thread_local! {
        pub static MOCK_CERTS: RefCell<Option<Vec<String>>> = const { RefCell::new(None) };
    }

    pub fn load_certificates(glob_pattern: &str) -> anyhow::Result<Vec<String>> {
        MOCK_CERTS.with(|cell| {
            if let Some(ref certs) = *cell.borrow() {
                Ok(certs.clone())
            } else if glob_pattern == "etc/pes-certs/**/*.pem" {
                Ok(vec![crate::certs::tests::CERTS_PEM.to_string()])
            } else {
                Ok(Vec::new())
            }
        })
    }
}

#[cfg(test)]
use mocks::*;

#[cfg(test)]
mod tests {
    use super::*;

    // --- Mock Helpers for get_pes_fields Tests ---

    fn mock_binary_ref_value() -> BinaryReferenceValue {
        use oak_proto_rust::oak::attestation::v1::{
            EndorsementReferenceValue, TLogReferenceValues,
        };
        BinaryReferenceValue {
            r#type: Some(binary_reference_value::Type::Endorsement(EndorsementReferenceValue {
                tlog: Some(TLogReferenceValues {
                    pes: Some(PesReferenceValue::default()),
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
                        pes: Some(PesReferenceValue::default()),
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
                    pes: Some(PesReferenceValue::default()),
                    ..Default::default()
                }),
                ..Default::default()
            })),
        }
    }

    #[test]
    fn test_get_pes_fields_empty() {
        let mut policy = Policy::default();
        let fields = get_pes_fields(&mut policy);
        assert!(fields.is_empty());
    }

    #[test]
    #[allow(deprecated)]
    fn test_get_pes_fields_extracts_all_layers() {
        use oak_proto_rust::oak::attestation::v1::{
            AmdSevReferenceValues, CbLayer1TransparentReferenceValues,
            CbLayer2TransparentReferenceValues, CbTransparentReferenceValues,
            KernelLayerReferenceValues, ReferenceValues, RootLayerReferenceValues,
        };

        // 1. Construct a Policy where all 6 possible PES locations are
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
                        runtime_agent: Some(mock_binary_ref_value()),
                        runtime_agent_binary: Some(mock_binary_ref_value()),
                        userspace: Some(mock_binary_ref_value()),
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

        // 2. Invoke get_pes_fields
        let fields = get_pes_fields(&mut policy);

        // 3. Assert that all 9 fields across the 4 layers were successfully
        //    extracted
        assert_eq!(fields.len(), 9);
    }

    #[test]
    fn test_get_pes_fields_oak_containers_extracts_all_layers() {
        use oak_proto_rust::oak::attestation::v1::{
            AmdSevReferenceValues, ContainerLayerReferenceValues, IntelTdxReferenceValues,
            KernelLayerReferenceValues, OakContainersReferenceValues, ReferenceValues,
            RootLayerReferenceValues, SystemLayerReferenceValues,
        };

        let mut policy = Policy {
            oak_reference_values: Some(ReferenceValues {
                r#type: Some(reference_values::Type::OakContainers(OakContainersReferenceValues {
                    root_layer: Some(RootLayerReferenceValues {
                        amd_sev: Some(AmdSevReferenceValues {
                            stage0: Some(mock_binary_ref_value()),
                            ..Default::default()
                        }),
                        intel_tdx: Some(IntelTdxReferenceValues {
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
                    system_layer: Some(SystemLayerReferenceValues {
                        system_image: Some(mock_binary_ref_value()),
                    }),
                    container_layer: Some(ContainerLayerReferenceValues {
                        binary: Some(mock_binary_ref_value()),
                        configuration: Some(mock_binary_ref_value()),
                    }),
                })),
            }),
            ..Default::default()
        };

        let fields = get_pes_fields(&mut policy);
        assert_eq!(fields.len(), 7);
    }

    #[test]
    fn test_get_pes_fields_partially_populated() {
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

        // 2. Invoke get_pes_fields
        let fields = get_pes_fields(&mut policy);

        // 3. Assert that exactly 3 fields were extracted (from kernel and
        //    layer2)
        assert_eq!(fields.len(), 3);
    }

    #[test]
    fn test_load_rsa_sha2_256_keyset_empty() {
        let result = load_rsa_sha2_256_keyset(&[], SystemTime::UNIX_EPOCH).unwrap();
        assert!(result.is_none());
    }

    #[test]
    fn test_load_rsa_sha2_256_keyset_all_expired_returns_empty_keyset() {
        let (_, e_end) =
            crate::certs::tests::cert_validity(crate::certs::tests::ENDORSEMENT_PES_CERT_PEM);
        let result = load_rsa_sha2_256_keyset(
            &[crate::certs::tests::CERTS_PEM.to_string()],
            e_end + std::time::Duration::from_secs(1),
        )
        .unwrap();
        assert_eq!(result, Some(VerifyingKeySet::default()));
    }

    #[test]
    fn test_load_rsa_sha2_256_keyset_multiple_certs() {
        let (e_start, e_end) =
            crate::certs::tests::cert_validity(crate::certs::tests::ENDORSEMENT_PES_CERT_PEM);
        let certs = [crate::certs::tests::CERTS_PEM.to_string()];

        for (now, should_verify) in
            [(e_start, true), (e_end + std::time::Duration::from_secs(1), false)]
        {
            let mut endorsement_data =
                test_util::endorsement_data::EndorsementData::load_for_pes_verification();
            endorsement_data.ref_value.tlog.as_mut().unwrap().pes.as_mut().unwrap().key_set =
                load_rsa_sha2_256_keyset(&certs, now).unwrap();
            let result = oak_attestation_verification::verify_endorsement(
                endorsement_data.make_valid_time().into_unix_millis(),
                &endorsement_data.signed_endorsement,
                &endorsement_data.ref_value,
            );
            assert_eq!(result.is_ok(), should_verify);
        }
    }

    #[test]
    fn test_inject_pes_keys_success() {
        use oak_proto_rust::oak::attestation::v1::{
            AmdSevReferenceValues, BinaryReferenceValue, CbTransparentReferenceValues,
            EndorsementReferenceValue, PesReferenceValue, ReferenceValues,
            RootLayerReferenceValues, TLogReferenceValues,
        };

        let (valid_now, _) =
            crate::certs::tests::cert_validity(crate::certs::tests::ENDORSEMENT_PES_CERT_PEM);

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
        inject_pes_keys(&mut policy, valid_now).expect("failed to inject keys");

        // 3. Construct the expected Policy object (with the key set injected)
        let expected_key_set =
            load_rsa_sha2_256_keyset(&[crate::certs::tests::CERTS_PEM.to_string()], valid_now)
                .unwrap()
                .unwrap();

        let expected_policy = Policy {
            oak_reference_values: Some(ReferenceValues {
                r#type: Some(reference_values::Type::Cbt(CbTransparentReferenceValues {
                    root_layer: Some(RootLayerReferenceValues {
                        amd_sev: Some(AmdSevReferenceValues {
                            stage0: Some(BinaryReferenceValue {
                                r#type: Some(binary_reference_value::Type::Endorsement(
                                    EndorsementReferenceValue {
                                        tlog: Some(TLogReferenceValues {
                                            pes: Some(PesReferenceValue {
                                                key_set: Some(expected_key_set),
                                                ..Default::default()
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
    fn test_inject_pes_keys_no_certs() {
        use oak_proto_rust::oak::attestation::v1::{
            AmdSevReferenceValues, CbTransparentReferenceValues, ReferenceValues,
            RootLayerReferenceValues,
        };

        // Force the mocked load_certificates to return an empty list
        MOCK_CERTS.with(|cell| *cell.borrow_mut() = Some(Vec::new()));
        // Ensure we clean it up after the test runs
        struct Reset;
        impl Drop for Reset {
            fn drop(&mut self) {
                MOCK_CERTS.with(|cell| *cell.borrow_mut() = None);
            }
        }
        let _reset = Reset;

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

        let initial_policy = policy.clone();

        // 2. Invoke the public API
        inject_pes_keys(&mut policy, SystemTime::UNIX_EPOCH).expect("failed to inject keys");

        // 3. Assert that the policy was not modified at all (matches the
        //    initial state exactly)
        assert_eq!(policy, initial_policy);
    }

    #[test]
    fn test_inject_pes_keys_includes_shadow_layer2() {
        use avs_proto_rust::avs::ShadowPolicy;
        use oak_proto_rust::oak::attestation::v1::{
            AmdSevReferenceValues, CbLayer2TransparentReferenceValues,
            CbTransparentReferenceValues, ReferenceValues, RootLayerReferenceValues,
        };

        let (valid_now, _) =
            crate::certs::tests::cert_validity(crate::certs::tests::ENDORSEMENT_PES_CERT_PEM);

        // A policy with PES fields in both the main reference values and the
        // shadow layer-2 candidate.
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
            shadow: Some(ShadowPolicy {
                layer2: Some(CbLayer2TransparentReferenceValues {
                    binary_mpms: vec![mock_mpm_ref_value(), mock_mpm_ref_value()],
                    ..Default::default()
                }),
            }),
            ..Default::default()
        };

        assert_eq!(get_pes_fields(&mut policy).len(), 3);

        inject_pes_keys(&mut policy, valid_now).expect("failed to inject keys");

        let expected_key_set =
            load_rsa_sha2_256_keyset(&[crate::certs::tests::CERTS_PEM.to_string()], valid_now)
                .unwrap()
                .unwrap();
        let fields = get_pes_fields(&mut policy);
        assert_eq!(fields.len(), 3);
        for field in fields {
            assert_eq!(field.key_set.as_ref(), Some(&expected_key_set));
        }
    }
}
