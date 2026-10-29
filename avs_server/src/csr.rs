//
// Copyright 2026 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//

use std::{sync::Arc, time::Duration};

use crate::{ca::KeyPair, operator_info::OperatorInfo};
use anyhow::Context;
use avs_proto_rust::avs::CertificateProfile;
use oak_attestation_verification::{
    create_amd_verifier, create_insecure_verifier, create_intel_tdx_verifier, extract_evidence,
    results::{get_user_data_payload, get_validity, unique_signing_public_key},
    verifier::verify_user_data_certificate,
    AmdSevSnpPolicy, AmdSevSnpTransparentDiceAttestationVerifier, FirmwarePolicy,
    TransparentLayer1Policy, TransparentLayer2Policy, TransparentStage0Policy,
};
use oak_attestation_verification_types::verifier::AttestationVerifier;
use oak_proto_rust::oak::attestation::v1::{
    attestation_results::Status, AmdSevReferenceValues, AttestationResults, BinaryReferenceValue,
    CbLayer1TransparentReferenceValues, CbLayer2TransparentReferenceValues,
    CbTransparentReferenceValues, Endorsements, Evidence, KernelLayerReferenceValues,
    ReferenceValues, TLogVerificationResults, TeePlatform,
};
use oak_time_std::clock::SystemTimeClock;
use p256::ecdsa::VerifyingKey;

// Three months (90 days) fallback validity.
const FALLBACK_VALIDITY: Duration = Duration::from_secs(90 * 24 * 60 * 60);

/// Identity fields derived from attestation verification, used to construct
/// the role. The role may be a SPIFFE ID or a DNS name. The role should always
/// be placed in the provisioned certificate's SAN extension.
pub(crate) struct ProvisionedIdentity {
    pub(crate) public_key: KeyPair,
    pub(crate) certificate_profile: CertificateProfile,
    pub(crate) operator_domain: String,
    pub(crate) operator_role: String,
    pub(crate) publisher_domain: String,
    pub(crate) publisher_role: String,
    pub(crate) workload_name: String,
    pub(crate) not_before_sec: i64,
    pub(crate) not_after_sec: i64,
}

/// Constructs an `AmdSevSnpTransparentDiceAttestationVerifier` from individual
/// reference value components.
fn create_transparent_verifier(
    amd_sev_rvs: &AmdSevReferenceValues,
    firmware_rvs: &BinaryReferenceValue,
    kernel_layer_rvs: &KernelLayerReferenceValues,
    layer1_rvs: &CbLayer1TransparentReferenceValues,
    layer2_rvs: &CbLayer2TransparentReferenceValues,
) -> AmdSevSnpTransparentDiceAttestationVerifier {
    let platform_policy = AmdSevSnpPolicy::new(amd_sev_rvs);
    let firmware_policy = FirmwarePolicy::new(firmware_rvs);
    let stage0_policy = TransparentStage0Policy::new(kernel_layer_rvs);
    let layer1_policy = TransparentLayer1Policy::new(layer1_rvs);
    let layer2_policy = TransparentLayer2Policy::new(layer2_rvs);

    AmdSevSnpTransparentDiceAttestationVerifier::new(
        platform_policy,
        Box::new(firmware_policy),
        // Event policies are matched to transparent event log entries by
        // index, so ordering must match: stage 0, layer 1, layer 2.
        vec![Box::new(stage0_policy), Box::new(layer1_policy), Box::new(layer2_policy)],
        Arc::new(SystemTimeClock),
    )
}

/// Extracts individual reference value components from
/// `CbTransparentReferenceValues` and constructs an
/// `AmdSevSnpTransparentDiceAttestationVerifier`.
fn create_cbt_verifier(
    cbt_ref_values: &CbTransparentReferenceValues,
) -> anyhow::Result<AmdSevSnpTransparentDiceAttestationVerifier> {
    let root_layer_rvs =
        cbt_ref_values.root_layer.as_ref().context("cbt reference values missing root_layer")?;
    let amd_sev_rvs =
        root_layer_rvs.amd_sev.as_ref().context("root_layer reference values missing amd_sev")?;
    let firmware_rvs =
        amd_sev_rvs.stage0.as_ref().context("amd_sev reference values missing stage0")?;
    let kernel_layer_rvs = cbt_ref_values
        .kernel_layer
        .as_ref()
        .context("cbt reference values missing kernel_layer")?;
    let layer1_rvs =
        cbt_ref_values.layer1.as_ref().context("cbt reference values missing layer1")?;
    let layer2_rvs =
        cbt_ref_values.layer2.as_ref().context("cbt reference values missing layer2")?;

    Ok(create_transparent_verifier(
        amd_sev_rvs,
        firmware_rvs,
        kernel_layer_rvs,
        layer1_rvs,
        layer2_rvs,
    ))
}

/// Decorator around an Oak Containers platform `AttestationVerifier` that also
/// verifies `Evidence.signed_user_data_certificate` against the verified
/// container instance signing public key.
struct OakContainersAttestationVerifier {
    inner: Box<dyn AttestationVerifier>,
}

impl OakContainersAttestationVerifier {
    fn new(inner: Box<dyn AttestationVerifier>) -> Self {
        Self { inner }
    }
}

impl AttestationVerifier for OakContainersAttestationVerifier {
    fn verify(
        &self,
        evidence: &Evidence,
        endorsements: &Endorsements,
    ) -> anyhow::Result<AttestationResults> {
        let mut attestation_results = self.inner.verify(evidence, endorsements)?;
        anyhow::ensure!(
            attestation_results.status == i32::from(Status::Success),
            "attestation verification failed with status {:?}: {}",
            attestation_results.status,
            attestation_results.reason
        );
        verify_oak_containers_user_data(evidence, &mut attestation_results)?;
        Ok(attestation_results)
    }
}

/// Constructs the appropriate `AttestationVerifier` for the policy's
/// `ReferenceValues` (`Cbt` or `OakContainers`) and optional TEE platform.
fn create_verifier(
    oak_ref_values: &ReferenceValues,
    tee_platform: Option<TeePlatform>,
) -> anyhow::Result<Box<dyn AttestationVerifier>> {
    use oak_proto_rust::oak::attestation::v1::reference_values;

    match oak_ref_values.r#type.as_ref() {
        Some(reference_values::Type::Cbt(cbt_ref_values)) => {
            Ok(Box::new(create_cbt_verifier(cbt_ref_values)?))
        }
        Some(reference_values::Type::OakContainers(_)) => {
            let platform = tee_platform.context("missing TEE platform for Oak Containers")?;
            let platform_verifier: Box<dyn AttestationVerifier> = match platform {
                TeePlatform::AmdSevSnp => {
                    Box::new(create_amd_verifier(SystemTimeClock, oak_ref_values)?)
                }
                TeePlatform::IntelTdx => {
                    Box::new(create_intel_tdx_verifier(SystemTimeClock, oak_ref_values)?)
                }
                TeePlatform::None => {
                    Box::new(create_insecure_verifier(SystemTimeClock, oak_ref_values)?)
                }
                platform => {
                    anyhow::bail!("unsupported TEE platform for Oak Containers: {:?}", platform);
                }
            };
            Ok(Box::new(OakContainersAttestationVerifier::new(platform_verifier)))
        }
        _ => anyhow::bail!("policy oak_reference_values must be either Cbt or OakContainers"),
    }
}

/// Verifies `Evidence.signed_user_data_certificate` against the verified
/// Oak Containers instance signing public key (`unique_signing_public_key` from
/// `ContainerLayerData` or `extract_evidence` from `application_keys`) and
/// appends the resulting `EventAttestationResults` to `attestation_results`.
fn verify_oak_containers_user_data(
    evidence: &Evidence,
    attestation_results: &mut AttestationResults,
) -> anyhow::Result<()> {
    anyhow::ensure!(
        !evidence.signed_user_data_certificate.is_empty(),
        "missing signed_user_data_certificate in Oak Containers evidence"
    );

    // On both AMD SEV-SNP and Intel TDX, `ContainerPolicy::verify` extracts
    // `ContainerLayerData.signing_public_key` into the event attestation
    // results (`unique_signing_public_key`). Fall back to `extract_evidence`
    // (`application_keys.signing_public_key_certificate`, verified by
    // `verify_dice_chain`) for older SEV-SNP evidence where
    // `ContainerLayerData.signing_public_key` was not populated.
    let signing_public_key_bytes = match unique_signing_public_key(attestation_results) {
        Ok(bytes) => bytes.clone(),
        Err(_) => {
            extract_evidence(evidence)
                .context("extracting signing public key from Oak Containers evidence")?
                .signing_public_key
        }
    };

    let signing_verifying_key =
        VerifyingKey::from_sec1_bytes(&signing_public_key_bytes).map_err(|err| {
            anyhow::anyhow!("failed to parse Oak Containers signing public key: {err}")
        })?;

    let user_data_result = verify_user_data_certificate(
        &evidence.signed_user_data_certificate,
        &signing_verifying_key,
    )
    .context("verifying signed user data certificate for Oak Containers")?;
    attestation_results.event_attestation_results.push(user_data_result);

    Ok(())
}

/// Extracts the validity period by intersecting the endorsement validity
/// windows returned across all event attestation results. If no endorsement
/// validity windows are present, falls back to `fallback_duration`.
fn extract_validity_with_fallback(
    attestation_results: &AttestationResults,
    current_time_sec: i64,
    fallback_duration: Duration,
) -> anyhow::Result<(i64, i64)> {
    let mut not_before_sec = current_time_sec;
    let mut not_after_sec = current_time_sec + (fallback_duration.as_secs() as i64);

    for event_attestation_result in &attestation_results.event_attestation_results {
        if let Some(validity) = get_validity(event_attestation_result) {
            if let Some(nb) = &validity.not_before {
                not_before_sec = std::cmp::max(not_before_sec, nb.seconds);
            }
            if let Some(na) = &validity.not_after {
                not_after_sec = std::cmp::min(not_after_sec, na.seconds);
            }
        }
    }

    anyhow::ensure!(
        not_after_sec > not_before_sec,
        "invalid validity window: not_after ({not_after_sec}) must be greater than not_before ({not_before_sec})"
    );
    anyhow::ensure!(
        not_after_sec > current_time_sec,
        "endorsement validity has expired: not_after ({not_after_sec}) is in the past (now is {current_time_sec})"
    );

    Ok((not_before_sec, not_after_sec))
}

fn collect_tlog_verification_results(
    attestation_results: AttestationResults,
) -> Vec<TLogVerificationResults> {
    attestation_results
        .event_attestation_results
        .into_iter()
        .flat_map(|event_result| event_result.tlog_verifications)
        .collect()
}

/// Validate CSR request using policy-based reference values and return the
/// provisioned identity.
///
/// Looks up the policy by `policy_name`, extracts the reference values from
/// the policy's `oak_reference_values` field, constructs a verifier, and
/// verifies the evidence against those reference values. The returned
/// `ProvisionedIdentity` is populated from the policy's identity fields.
///
/// Also returns the t-log verification results reported by Oak.
#[allow(clippy::too_many_arguments)]
pub(crate) fn validate_csr_request(
    csr_der: &[u8],
    evidence: &Evidence,
    endorsements: &Endorsements,
    nonce: Option<&[u8]>,
    policy_name: &str,
    certificate_profile: CertificateProfile,
    operator_info: &OperatorInfo,
    policies_config: &policies::PoliciesConfig,
) -> anyhow::Result<(ProvisionedIdentity, Vec<TLogVerificationResults>)> {
    use anyhow::Context;

    let csr_public_key = verify_csr_and_get_public_key(csr_der)?;

    let policy = policies::get_policy_with_config(policy_name, policies_config)
        .context("looking up policy for the given policy_name")?;

    let operator_policy =
        policy.operator_policy.as_ref().context("retrieving operator_policy from policy")?;

    let is_operator_authorized = operator_policy
        .rules
        .iter()
        .any(|rule| rule.domain == operator_info.domain() && rule.role == operator_info.role());

    anyhow::ensure!(
        is_operator_authorized,
        "operator '{}/{}' is not authorized by operator_policy: {:?}",
        operator_info.domain(),
        operator_info.role(),
        operator_policy
    );

    let oak_ref_values =
        policy.oak_reference_values.as_ref().context("policy is missing oak_reference_values")?;
    let tee_platform = evidence.root_layer.as_ref().map(|r| r.platform());
    let verifier = create_verifier(oak_ref_values, tee_platform)?;
    let attestation_results = verifier.verify(evidence, endorsements)?;

    if attestation_results.status != i32::from(Status::Success) {
        anyhow::bail!(
            "attestation verification failed with status {:?}: {}",
            attestation_results.status,
            attestation_results.reason
        );
    }

    verify_data_binding(&attestation_results, &csr_public_key, nonce)?;

    let current_time_sec = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .context("getting current system time")?
        .as_secs() as i64;
    let (not_before_sec, not_after_sec) =
        extract_validity_with_fallback(&attestation_results, current_time_sec, FALLBACK_VALIDITY)?;

    let tlog_verification_results = collect_tlog_verification_results(attestation_results);

    let identity = ProvisionedIdentity {
        public_key: csr_public_key,
        certificate_profile,
        operator_domain: operator_info.domain().to_string(),
        operator_role: operator_info.role().to_string(),
        publisher_domain: policy.publisher_domain,
        publisher_role: policy.publisher_role,
        workload_name: policy.workload_name,
        not_before_sec,
        not_after_sec,
    };
    Ok((identity, tlog_verification_results))
}

// Parses length-prefixed user data and returns
// a tuple of (nonce, public_key) as slices.
fn extract_payload<'a>(mut data: &'a [u8]) -> anyhow::Result<(&'a [u8], &'a [u8])> {
    // Helper to extract a single length-prefixed chunk
    let take_chunk = |slice: &mut &'a [u8]| -> anyhow::Result<&'a [u8]> {
        if slice.len() < 4 {
            anyhow::bail!("Buffer too short for length header");
        }

        // Split the first 4 bytes to get the length
        let (len_bytes, rest) = slice.split_at(4);
        let len = u32::from_be_bytes(
            len_bytes.try_into().map_err(|_| anyhow::anyhow!("Internal conversion error"))?,
        ) as usize;
        if rest.len() < len {
            anyhow::bail!("Buffer too short for payload body");
        }

        // Split the payload from the remaining data
        let (payload, remaining) = rest.split_at(len);
        *slice = remaining; // Advance the "cursor"

        Ok(payload)
    };

    let nonce = take_chunk(&mut data)?;
    let public_key = take_chunk(&mut data)?;

    if !data.is_empty() {
        anyhow::bail!("Trailing data detected in buffer");
    }

    Ok((nonce, public_key))
}

// Extracts the bound data from the attestation results and verifies that it
// matches the CSR public key and the optional nonce.
// The data format is: Length(Nonce) + Nonce + Length(Public_Key) + Public_Key.
fn verify_data_binding(
    attestation_results: &AttestationResults,
    csr_public_key: &KeyPair,
    nonce: Option<&[u8]>,
) -> anyhow::Result<()> {
    let mut payload = Vec::new();
    for event_attestation_result in &attestation_results.event_attestation_results {
        // TODO: b/484977728 - generalizing quote fetching for quotes that are
        // not in `Evidence` under the USER_DATA_PAYLOAD_ID tag.
        if let Some(user_data_payload) = get_user_data_payload(event_attestation_result) {
            payload = user_data_payload.clone();
            break;
        }
    }

    if payload.is_empty() {
        anyhow::bail!("no user data payload found in attestation results");
    }

    // No nonce is expected, check if the public key matches.
    let Some(expected_nonce) = nonce else {
        // Retrieve the quoted public key from the attestation results.
        // Here we assume that the public key in the attestation results is in
        // DER format.
        let quoted_public_key = KeyPair::from_bytes(&payload)
            .context("failed to parse public key from attestation results")?;

        if quoted_public_key != *csr_public_key {
            anyhow::bail!("quoted key does not match the key in the certificate signing request");
        }
        return Ok(());
    };

    let (actual_nonce, actual_csr_public_key) = extract_payload(&payload)?;
    if actual_nonce != expected_nonce {
        anyhow::bail!("nonce mismatch: expected {:?}, got {:?}", expected_nonce, actual_nonce);
    }

    let actual_public_key = KeyPair::from_bytes(actual_csr_public_key)
        .context("failed to parse public key from attestation results")?;
    if *csr_public_key != actual_public_key {
        anyhow::bail!("quoted key does not match the key in the certificate signing request");
    }

    Ok(())
}

fn verify_csr_and_get_public_key(csr_der: &[u8]) -> anyhow::Result<KeyPair> {
    unsafe {
        let mut p = csr_der.as_ptr();
        // This memory must be freed by calling X509_REQ_free().
        let csr = bssl_sys::d2i_X509_REQ(std::ptr::null_mut(), &mut p, csr_der.len() as i64);

        if csr.is_null() {
            let err = bssl_sys::ERR_get_error();
            if err != 0 {
                let err_str = bssl_sys::ERR_reason_error_string(err);
                if !err_str.is_null() {
                    anyhow::bail!(
                        "failed to parse CSR: {}",
                        std::ffi::CStr::from_ptr(err_str).to_string_lossy()
                    );
                }
            }
            anyhow::bail!("failed to parse CSR.");
        }
        // Verify CSR signature
        let pkey = bssl_sys::X509_REQ_get_pubkey(csr);
        if pkey.is_null() {
            bssl_sys::X509_REQ_free(csr);
            anyhow::bail!("failed to get public key form CSR.");
        }

        if bssl_sys::X509_REQ_verify(csr, pkey) != 1 {
            bssl_sys::EVP_PKEY_free(pkey);
            bssl_sys::X509_REQ_free(csr);
            anyhow::bail!("CSR signature is invalid.");
        }

        bssl_sys::X509_REQ_free(csr);

        Ok(KeyPair::new(pkey))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use oak_proto_rust::oak::{attestation::v1::EventAttestationResults, Validity};
    use prost_types::Timestamp;

    fn make_timestamp(seconds: i64) -> Timestamp {
        Timestamp { seconds, nanos: 0 }
    }

    #[test]
    fn extract_validity_with_fallback_no_endorsements_uses_fallback() {
        let attestation_results = AttestationResults {
            event_attestation_results: vec![
                EventAttestationResults::default(),
                EventAttestationResults::default(),
            ],
            ..Default::default()
        };
        let now = 1_000_000;
        let fallback = Duration::from_secs(500_000);
        let (nb, na) = extract_validity_with_fallback(&attestation_results, now, fallback).unwrap();
        assert_eq!(nb, now);
        assert_eq!(na, now + 500_000);
    }

    #[test]
    fn extract_validity_with_fallback_single_endorsement() {
        let attestation_results = AttestationResults {
            event_attestation_results: vec![EventAttestationResults {
                valid: Some(Validity {
                    not_before: Some(make_timestamp(900_000)),
                    not_after: Some(make_timestamp(2_000_000)),
                }),
                ..Default::default()
            }],
            ..Default::default()
        };
        let now = 1_000_000;
        let fallback = Duration::from_secs(5_000_000);
        let (nb, na) = extract_validity_with_fallback(&attestation_results, now, fallback).unwrap();
        assert_eq!(nb, now);
        assert_eq!(na, 2_000_000);
    }

    #[test]
    fn extract_validity_with_fallback_intersects_multiple_windows() {
        let attestation_results = AttestationResults {
            event_attestation_results: vec![
                EventAttestationResults {
                    valid: Some(Validity {
                        not_before: Some(make_timestamp(1_050_000)),
                        not_after: Some(make_timestamp(3_000_000)),
                    }),
                    ..Default::default()
                },
                EventAttestationResults {
                    valid: Some(Validity {
                        not_before: Some(make_timestamp(950_000)),
                        not_after: Some(make_timestamp(2_000_000)),
                    }),
                    ..Default::default()
                },
            ],
            ..Default::default()
        };
        let now = 1_000_000;
        let fallback = Duration::from_secs(5_000_000);
        let (nb, na) = extract_validity_with_fallback(&attestation_results, now, fallback).unwrap();
        assert_eq!(nb, 1_050_000);
        assert_eq!(na, 2_000_000);
    }

    #[test]
    fn extract_validity_with_fallback_rejects_expired_window() {
        let attestation_results = AttestationResults {
            event_attestation_results: vec![EventAttestationResults {
                valid: Some(Validity {
                    not_before: Some(make_timestamp(500_000)),
                    not_after: Some(make_timestamp(900_000)),
                }),
                ..Default::default()
            }],
            ..Default::default()
        };
        let now = 1_000_000;
        let fallback = Duration::from_secs(500_000);
        assert!(extract_validity_with_fallback(&attestation_results, now, fallback).is_err());
    }

    #[test]
    fn extract_validity_with_fallback_rejects_inverted_window() {
        let attestation_results = AttestationResults {
            event_attestation_results: vec![
                EventAttestationResults {
                    valid: Some(Validity {
                        not_before: Some(make_timestamp(2_000_000)),
                        not_after: Some(make_timestamp(3_000_000)),
                    }),
                    ..Default::default()
                },
                EventAttestationResults {
                    valid: Some(Validity {
                        not_before: Some(make_timestamp(1_000_000)),
                        not_after: Some(make_timestamp(1_500_000)),
                    }),
                    ..Default::default()
                },
            ],
            ..Default::default()
        };
        let now = 1_000_000;
        let fallback = Duration::from_secs(5_000_000);
        assert!(extract_validity_with_fallback(&attestation_results, now, fallback).is_err());
    }

    #[test]
    fn collect_tlog_verification_results_flattens_events() {
        let record = |subject: &str| TLogVerificationResults {
            subject: subject.to_string(),
            ..Default::default()
        };
        let attestation_results = AttestationResults {
            event_attestation_results: vec![
                EventAttestationResults {
                    tlog_verifications: vec![record("stage0"), record("kernel")],
                    ..Default::default()
                },
                EventAttestationResults::default(),
                EventAttestationResults {
                    tlog_verifications: vec![record("container")],
                    ..Default::default()
                },
            ],
            ..Default::default()
        };

        assert_eq!(
            collect_tlog_verification_results(attestation_results),
            vec![record("stage0"), record("kernel"), record("container")]
        );
    }

    #[test]
    fn verify_oak_containers_user_data_succeeds_and_extracts_payload() {
        use coset::{iana, CborSerializable, CoseSign1Builder, HeaderBuilder};
        use oak_attestation_verification::results::set_signing_public_key;
        use p256::ecdsa::{signature::Signer, SigningKey};

        let signing_key = SigningKey::from_bytes((&[0x42u8; 32]).into()).unwrap();
        let verifying_key_sec1 = signing_key.verifying_key().to_sec1_bytes().to_vec();

        let payload = b"bound-nonce-and-public-key-payload";
        let protected = HeaderBuilder::new().algorithm(iana::Algorithm::ES256).build();
        let cose_sign1 = CoseSign1Builder::new()
            .protected(protected)
            .payload(payload.to_vec())
            .create_signature(&[], |data| {
                let sig: p256::ecdsa::Signature = signing_key.sign(data);
                sig.to_bytes().to_vec()
            })
            .build();

        let evidence = Evidence {
            signed_user_data_certificate: cose_sign1.to_vec().unwrap(),
            ..Default::default()
        };

        let mut container_event_result = EventAttestationResults::default();
        set_signing_public_key(&mut container_event_result, &verifying_key_sec1);
        let mut attestation_results = AttestationResults {
            status: Status::Success.into(),
            event_attestation_results: vec![container_event_result],
            ..Default::default()
        };

        verify_oak_containers_user_data(&evidence, &mut attestation_results)
            .expect("user data verification should succeed");

        let extracted = attestation_results
            .event_attestation_results
            .iter()
            .find_map(get_user_data_payload)
            .expect("user data payload artifact should be present");
        assert_eq!(extracted.as_slice(), payload);
    }

    #[test]
    fn verify_oak_containers_user_data_rejects_missing_or_wrong_signature() {
        use coset::{iana, CborSerializable, CoseSign1Builder, HeaderBuilder};
        use oak_attestation_verification::results::set_signing_public_key;
        use p256::ecdsa::{signature::Signer, SigningKey};

        let signing_key = SigningKey::from_bytes((&[0x42u8; 32]).into()).unwrap();
        let wrong_key = SigningKey::from_bytes((&[0x99u8; 32]).into()).unwrap();
        let verifying_key_sec1 = signing_key.verifying_key().to_sec1_bytes().to_vec();

        let mut container_event_result = EventAttestationResults::default();
        set_signing_public_key(&mut container_event_result, &verifying_key_sec1);
        let mut attestation_results = AttestationResults {
            status: Status::Success.into(),
            event_attestation_results: vec![container_event_result],
            ..Default::default()
        };

        // 1. Missing signed_user_data_certificate
        let empty_evidence = Evidence::default();
        assert!(verify_oak_containers_user_data(&empty_evidence, &mut attestation_results).is_err());

        // 2. Signed with wrong key
        let protected = HeaderBuilder::new().algorithm(iana::Algorithm::ES256).build();
        let cose_sign1 = CoseSign1Builder::new()
            .protected(protected)
            .payload(b"payload".to_vec())
            .create_signature(&[], |data| {
                let sig: p256::ecdsa::Signature = wrong_key.sign(data);
                sig.to_bytes().to_vec()
            })
            .build();
        let bad_evidence = Evidence {
            signed_user_data_certificate: cose_sign1.to_vec().unwrap(),
            ..Default::default()
        };
        assert!(verify_oak_containers_user_data(&bad_evidence, &mut attestation_results).is_err());
    }

    struct StubAttestationVerifier {
        results: AttestationResults,
    }

    impl AttestationVerifier for StubAttestationVerifier {
        fn verify(&self, _: &Evidence, _: &Endorsements) -> anyhow::Result<AttestationResults> {
            Ok(self.results.clone())
        }
    }

    #[test]
    fn oak_containers_attestation_verifier_propagates_inner_failure() {
        let inner = StubAttestationVerifier {
            results: AttestationResults {
                status: Status::GenericFailure.into(),
                reason: "simulated stage0 mismatch".to_string(),
                ..Default::default()
            },
        };
        let verifier = OakContainersAttestationVerifier::new(Box::new(inner));
        let err = verifier
            .verify(&Evidence::default(), &Endorsements::default())
            .expect_err("should fail when inner verifier returns non-Success status");
        assert!(err.to_string().contains("simulated stage0 mismatch"));
    }

    #[test]
    fn create_verifier_oak_containers_checks_tee_platform() {
        use oak_proto_rust::oak::attestation::v1::{
            reference_values, ContainerLayerReferenceValues, InsecureReferenceValues,
            OakContainersReferenceValues, RootLayerReferenceValues, SystemLayerReferenceValues,
        };

        let oak_ref_values = ReferenceValues {
            r#type: Some(reference_values::Type::OakContainers(OakContainersReferenceValues {
                root_layer: Some(RootLayerReferenceValues {
                    insecure: Some(InsecureReferenceValues::default()),
                    ..Default::default()
                }),
                kernel_layer: Some(KernelLayerReferenceValues::default()),
                system_layer: Some(SystemLayerReferenceValues::default()),
                container_layer: Some(ContainerLayerReferenceValues::default()),
            })),
        };

        let err = create_verifier(&oak_ref_values, None).err().expect("missing tee_platform");
        assert!(err.to_string().contains("missing TEE platform for Oak Containers"));
        assert!(create_verifier(&oak_ref_values, Some(TeePlatform::Unspecified)).is_err());
        assert!(create_verifier(&oak_ref_values, Some(TeePlatform::None)).is_ok());
    }
}
