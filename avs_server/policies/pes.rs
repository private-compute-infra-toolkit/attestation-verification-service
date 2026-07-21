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

#[cfg(not(test))]
use crate::certs::{extract_spki_from_pem, load_certificates};

use oak_proto_rust::oak::attestation::v1::{
    binary_reference_value, kernel_binary_reference_value, mpm_reference_value, reference_values,
    BinaryReferenceValue, KernelBinaryReferenceValue, KeyType, MpmReferenceValue,
    PesReferenceValue, VerifyingKey, VerifyingKeySet,
};

/// Loads a single `VerifyingKeySet` from the provided certificate strings.
fn load_rsa_sha2_256_keyset(certs: &[String]) -> anyhow::Result<Option<VerifyingKeySet>> {
    if certs.is_empty() {
        return Ok(None);
    }

    let mut keys = Vec::new();
    for (index, pem_content) in certs.iter().enumerate() {
        let raw_key = extract_spki_from_pem(pem_content)?;
        keys.push(VerifyingKey {
            r#type: KeyType::RsaSha2256 as i32,
            key_id: index as u32,
            raw: raw_key,
        });
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
/// given `Policy`.
#[allow(deprecated)]
fn get_pes_fields(policy: &mut Policy) -> Vec<&mut PesReferenceValue> {
    let mut pes_fields = Vec::new();

    let Some(ref mut oak_ref_values) = policy.oak_reference_values else {
        return pes_fields;
    };

    let Some(reference_values::Type::Cbt(ref mut cbt_reference_values)) = oak_ref_values.r#type
    else {
        return pes_fields;
    };

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

/// Loads the PES verifying keys from the glob pattern and injects them into the
/// retrieved `pes` fields in the policy.
pub fn inject_pes_keys(policy: &mut Policy) -> anyhow::Result<()> {
    let glob_pattern = "etc/pes-certs/**/*.pem";
    let certs = load_certificates(glob_pattern)?;

    if let Some(key_set) = load_rsa_sha2_256_keyset(&certs)? {
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
                Ok(vec!["mock_cert_foo".to_string(), "mock_cert_bar".to_string()])
            } else {
                Ok(Vec::new())
            }
        })
    }

    pub fn extract_spki_from_pem(pem: &str) -> anyhow::Result<Vec<u8>> {
        Ok(format!("spki_of_{}", pem).into_bytes())
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

        // 1. Construct a Policy where all 6 possible PES locations are populated
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

        // 3. Assert that all 9 fields across the 4 layers were successfully extracted
        assert_eq!(fields.len(), 9);
    }

    #[test]
    fn test_get_pes_fields_partially_populated() {
        use oak_proto_rust::oak::attestation::v1::{
            CbLayer2TransparentReferenceValues, CbTransparentReferenceValues,
            KernelLayerReferenceValues, ReferenceValues,
        };

        // 1. Construct a Policy where only some layers and fields are populated:
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

        // 3. Assert that exactly 3 fields were extracted (from kernel and layer2)
        assert_eq!(fields.len(), 3);
    }

    #[test]
    fn test_load_rsa_sha2_256_keyset_empty() {
        let result = load_rsa_sha2_256_keyset(&[]).unwrap();
        assert!(result.is_none());
    }

    #[test]
    fn test_load_rsa_sha2_256_keyset_valid() {
        let certs = vec!["cert_foo".to_string(), "cert_bar".to_string()];
        let key_set = load_rsa_sha2_256_keyset(&certs).unwrap().unwrap();

        assert_eq!(key_set.keys.len(), 2);
        assert_eq!(key_set.keys[0].r#type, KeyType::RsaSha2256 as i32);
        assert_eq!(key_set.keys[0].key_id, 0);
        assert_eq!(key_set.keys[0].raw, b"spki_of_cert_foo");

        assert_eq!(key_set.keys[1].r#type, KeyType::RsaSha2256 as i32);
        assert_eq!(key_set.keys[1].key_id, 1);
        assert_eq!(key_set.keys[1].raw, b"spki_of_cert_bar");

        assert!(key_set.signed_timestamp.is_none());
    }

    #[test]
    fn test_inject_pes_keys_success() {
        use oak_proto_rust::oak::attestation::v1::{
            AmdSevReferenceValues, BinaryReferenceValue, CbTransparentReferenceValues,
            EndorsementReferenceValue, KeyType, PesReferenceValue, ReferenceValues,
            RootLayerReferenceValues, TLogReferenceValues, VerifyingKey, VerifyingKeySet,
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
        inject_pes_keys(&mut policy).expect("failed to inject keys");

        // 3. Construct the expected Policy object (with the key set injected)
        let expected_key_set = VerifyingKeySet {
            keys: vec![
                VerifyingKey {
                    r#type: KeyType::RsaSha2256 as i32,
                    key_id: 0,
                    raw: b"spki_of_mock_cert_foo".to_vec(),
                },
                VerifyingKey {
                    r#type: KeyType::RsaSha2256 as i32,
                    key_id: 1,
                    raw: b"spki_of_mock_cert_bar".to_vec(),
                },
            ],
            signed_timestamp: None,
        };

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
        inject_pes_keys(&mut policy).expect("failed to inject keys");

        // 3. Assert that the policy was not modified at all (matches the initial state
        //    exactly)
        assert_eq!(policy, initial_policy);
    }
}
