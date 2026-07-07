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

use std::sync::Arc;

use crate::ca::KeyPair;
use anyhow::Context;
use avs_proto_rust::avs::{OperatorInfo, PolicyHint};
#[cfg(not(feature = "enforce_policy"))]
use oak_attestation_verification::decode_event_proto;
use oak_attestation_verification::{
    results::get_user_data_payload, AmdSevSnpPolicy, AmdSevSnpTransparentDiceAttestationVerifier,
    FirmwarePolicy, TransparentLayer1Policy, TransparentLayer2Policy, TransparentStage0Policy,
};
use oak_attestation_verification_types::verifier::AttestationVerifier;
use oak_proto_rust::oak::attestation::v1::{
    attestation_results::Status, AttestationResults, BinaryReferenceValue,
    CbLayer1TransparentReferenceValues, CbLayer2TransparentReferenceValues, Endorsements, Evidence,
    KernelLayerReferenceValues,
};
#[cfg(not(feature = "enforce_policy"))]
use oak_proto_rust::oak::{
    attestation::v1::{
        binary_reference_value, kernel_binary_reference_value, mpm_reference_value,
        text_reference_value, CbLayer1TransparentEvent, CbLayer2TransparentEvent, Digests,
        KernelBinaryReferenceValue, KernelDigests, MpmReferenceValue, MpmVersionIds,
        SkipVerification, Stage0TransparentMeasurements, TextReferenceValue,
    },
    RawDigest,
};
use oak_time_std::clock::SystemTimeClock;

/// Controls which Extended Key Usage extension is set on a provisioned
/// certificate.
pub(crate) enum ConnectionMode {
    /// No EKU extension added.
    Unrestricted,
    /// serverAuth + clientAuth (mutual TLS).
    Mtls,
    /// serverAuth only (frontend TLS).
    Tls,
}

impl From<PolicyHint> for ConnectionMode {
    fn from(hint: PolicyHint) -> Self {
        match hint {
            PolicyHint::Unspecified
            | PolicyHint::PrivateArateaFrontendCbCertificate
            | PolicyHint::ProberCbCertificate
            | PolicyHint::DevelopmentCbCertificate => ConnectionMode::Unrestricted,
            PolicyHint::EzEnforcerCbCertificate | PolicyHint::DevelopmentMtlsCbCertificate => {
                ConnectionMode::Mtls
            }
            PolicyHint::EzTsmCbFrontendCertificate | PolicyHint::DevelopmentTlsCbCertificate => {
                ConnectionMode::Tls
            }
        }
    }
}

/// Identity fields derived from attestation verification, used to construct
/// the role. The role may be a SPIFFE ID or a DNS name. The role should always
/// be placed in the provisioned certificate's SAN extension.
pub(crate) struct ProvisionedIdentity {
    pub(crate) public_key: KeyPair,
    pub(crate) connection_mode: ConnectionMode,
    pub(crate) operator_domain: String,
    pub(crate) operator_role: String,
    pub(crate) publisher_domain: String,
    pub(crate) publisher_role: String,
    pub(crate) workload_name: String,
}

use oak_proto_rust::oak::attestation::v1::AmdSevReferenceValues;
#[cfg(feature = "enforce_policy")]
use oak_proto_rust::oak::attestation::v1::CbTransparentReferenceValues;

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
#[cfg(feature = "enforce_policy")]
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

/// Validate CSR request using policy-based reference values and return the
/// provisioned identity.
///
/// Looks up the policy by `policy_hint`, extracts the reference values from
/// the policy's `oak_reference_values` field, constructs a verifier, and
/// verifies the evidence against those reference values. The returned
/// `ProvisionedIdentity` is populated from the policy's identity fields.
#[cfg(feature = "enforce_policy")]
pub(crate) fn validate_csr_request(
    csr_der: &[u8],
    evidence: &Evidence,
    endorsements: &Endorsements,
    nonce: Option<&[u8]>,
    policy_hint: i32,
    operator_info: &OperatorInfo,
    policies_config: &policies::PoliciesConfig,
) -> anyhow::Result<ProvisionedIdentity> {
    use oak_proto_rust::oak::attestation::v1::reference_values;

    let csr_public_key = verify_csr_and_get_public_key(csr_der)?;

    let hint = PolicyHint::try_from(policy_hint)
        .map_err(|_| anyhow::anyhow!("unrecognized policy_hint value: {}", policy_hint))?;
    let policy = policies::get_policy_with_config(hint, policies_config)
        .context("looking up policy for the given policy_hint")?;

    let oak_ref_values =
        policy.oak_reference_values.as_ref().context("policy is missing oak_reference_values")?;
    let cbt_ref_values = match oak_ref_values.r#type.as_ref() {
        Some(reference_values::Type::Cbt(cbt)) => cbt,
        _ => anyhow::bail!("policy oak_reference_values is not the expected Cbt type"),
    };

    let verifier = create_cbt_verifier(cbt_ref_values)?;
    let attestation_results = verifier.verify(evidence, endorsements)?;

    if attestation_results.status != i32::from(Status::Success) {
        anyhow::bail!(
            "attestation verification failed with status {:?}: {}",
            attestation_results.status,
            attestation_results.reason
        );
    }

    verify_data_binding(&attestation_results, &csr_public_key, nonce)?;

    let connection_mode: ConnectionMode = hint.into();

    anyhow::ensure!(
        !operator_info.operator_domain.is_empty(),
        "operator_domain must be specified in operator_info"
    );
    let operator_domain = operator_info.operator_domain.clone();
    let operator_role = if operator_info.operator_role.is_empty() {
        "none".to_string()
    } else {
        operator_info.operator_role.clone()
    };

    Ok(ProvisionedIdentity {
        public_key: csr_public_key,
        connection_mode,
        operator_domain,
        operator_role,
        publisher_domain: policy.publisher_domain,
        publisher_role: policy.publisher_role,
        workload_name: policy.workload_name,
    })
}

/// CSR validation that derives reference values from the evidence itself.
/// Since the measurements in the evidence are used as both the actual and
/// expected values, verification always succeeds as long as the evidence is
/// well-formed.
///
/// TODO: b/515710997 - Remove this function once all attestation measurements
/// are properly endorsed.
#[cfg(not(feature = "enforce_policy"))]
pub(crate) fn always_certify_request(
    csr_der: &[u8],
    evidence: &Evidence,
    endorsements: &Endorsements,
    nonce: Option<&[u8]>,
    policy_hint: i32,
    operator_info: &OperatorInfo,
    policies_config: &policies::PoliciesConfig,
) -> anyhow::Result<ProvisionedIdentity> {
    let csr_public_key = verify_csr_and_get_public_key(csr_der)?;

    let root_layer = evidence.root_layer.as_ref().context("no root layer in evidence")?;
    let (amd_sev_ref_values, firmware_ref_values) =
        AmdSevSnpPolicy::evidence_to_reference_values(root_layer)
            .context("deriving reference values from evidence")?;

    let (stage0_ref_values, layer1_ref_values, layer2_ref_values) =
        evidence_to_transparent_reference_values(evidence)
            .context("extracting transparent reference values from evidence")?;

    let verifier = create_transparent_verifier(
        &amd_sev_ref_values,
        &firmware_ref_values,
        &stage0_ref_values,
        &layer1_ref_values,
        &layer2_ref_values,
    );
    let attestation_results = verifier.verify(evidence, endorsements)?;

    if attestation_results.status != i32::from(Status::Success) {
        anyhow::bail!(
            "attestation verification failed with status {:?}: {}",
            attestation_results.status,
            attestation_results.reason
        );
    }

    verify_data_binding(&attestation_results, &csr_public_key, nonce)?;

    let hint = PolicyHint::try_from(policy_hint)
        .map_err(|_| anyhow::anyhow!("unrecognized policy_hint value: {}", policy_hint))?;

    if matches!(
        hint,
        PolicyHint::DevelopmentCbCertificate
            | PolicyHint::DevelopmentMtlsCbCertificate
            | PolicyHint::DevelopmentTlsCbCertificate
    ) && !policies_config.include_development_policy
    {
        anyhow::bail!("policy not supported: {:?}", hint);
    }

    let connection_mode: ConnectionMode = hint.into();

    anyhow::ensure!(
        !operator_info.operator_domain.is_empty(),
        "operator_domain must be specified in operator_info"
    );
    let operator_domain = operator_info.operator_domain.clone();
    let operator_role = if operator_info.operator_role.is_empty() {
        "none".to_string()
    } else {
        operator_info.operator_role.clone()
    };

    Ok(ProvisionedIdentity {
        public_key: csr_public_key,
        connection_mode,
        operator_domain,
        operator_role,
        publisher_domain: "google-release".to_string(),
        publisher_role: "pcit-release-bot".to_string(),
        workload_name: "encrypted-zone".to_string(),
    })
}

/// Constructs a `BinaryReferenceValue` containing a single SHA-256 digest.
#[cfg(not(feature = "enforce_policy"))]
fn brv_from_digest(sha2_256: &[u8]) -> BinaryReferenceValue {
    BinaryReferenceValue {
        r#type: Some(binary_reference_value::Type::Digests(Digests {
            digests: vec![RawDigest { sha2_256: sha2_256.to_vec(), ..Default::default() }],
        })),
    }
}

/// Constructs a `KernelBinaryReferenceValue` containing single SHA-256 digests
/// for the kernel image and setup data.
#[cfg(not(feature = "enforce_policy"))]
fn kernel_brv_from_digest(
    image_sha2_256: &[u8],
    setup_data_sha2_256: &[u8],
) -> KernelBinaryReferenceValue {
    KernelBinaryReferenceValue {
        r#type: Some(kernel_binary_reference_value::Type::Digests(KernelDigests {
            image: Some(Digests {
                digests: vec![RawDigest {
                    sha2_256: image_sha2_256.to_vec(),
                    ..Default::default()
                }],
            }),
            setup_data: Some(Digests {
                digests: vec![RawDigest {
                    sha2_256: setup_data_sha2_256.to_vec(),
                    ..Default::default()
                }],
            }),
        })),
    }
}

/// Extracts measurement digests from the Evidence's transparent event log
/// and constructs matching reference values for each transparent policy layer.
#[cfg(not(feature = "enforce_policy"))]
fn evidence_to_transparent_reference_values(
    evidence: &Evidence,
) -> anyhow::Result<(
    KernelLayerReferenceValues,
    CbLayer1TransparentReferenceValues,
    CbLayer2TransparentReferenceValues,
)> {
    let event_log =
        evidence.transparent_event_log.as_ref().context("no transparent event log in evidence")?;

    anyhow::ensure!(
        event_log.encoded_events.len() >= 3,
        "expected at least 3 transparent events, found {}",
        event_log.encoded_events.len()
    );

    // Event 0: Stage0TransparentMeasurements -> KernelLayerReferenceValues
    let stage0 = decode_event_proto::<Stage0TransparentMeasurements>(
        "type.googleapis.com/oak.attestation.v1.Stage0TransparentMeasurements",
        &event_log.encoded_events[0],
    )
    .context("decoding Stage0TransparentMeasurements")?;

    let stage0_ref_values = KernelLayerReferenceValues {
        kernel: Some(kernel_brv_from_digest(&stage0.kernel_measurement, &stage0.setup_data_digest)),
        // The transparent form only has a cmdline *digest*, not the raw string.
        // The compare function requires Skipped when kernel_raw_cmd_line is None.
        kernel_cmd_line_text: Some(TextReferenceValue {
            r#type: Some(text_reference_value::Type::Skip(SkipVerification {})),
        }),
        init_ram_fs: Some(brv_from_digest(&stage0.ram_disk_digest)),
        memory_map: Some(brv_from_digest(&stage0.memory_map_digest)),
        acpi: Some(brv_from_digest(&stage0.acpi_digest)),
    };

    // Event 1: CbLayer1TransparentEvent -> CbLayer1TransparentReferenceValues
    let layer1 = decode_event_proto::<CbLayer1TransparentEvent>(
        "type.googleapis.com/oak.attestation.v1.CbLayer1TransparentEvent",
        &event_log.encoded_events[1],
    )
    .context("decoding CbLayer1TransparentEvent")?;

    #[allow(deprecated)]
    let layer1_ref_values = CbLayer1TransparentReferenceValues {
        runtime_agent: Some(brv_from_digest(&layer1.runtime_agent_measurement)),
        // TODO: b/498607119 - Populate from evidence once runtime_agent_binary_measurement
        // and userspace_measurement fields are populated.
        runtime_agent_binary: Some(BinaryReferenceValue {
            r#type: Some(binary_reference_value::Type::Skip(SkipVerification {})),
        }),
        userspace: Some(BinaryReferenceValue {
            r#type: Some(binary_reference_value::Type::Skip(SkipVerification {})),
        }),
    };

    // Event 2: CbLayer2TransparentEvent -> CbLayer2TransparentReferenceValues
    let layer2 = decode_event_proto::<CbLayer2TransparentEvent>(
        "type.googleapis.com/oak.attestation.v1.CbLayer2TransparentEvent",
        &event_log.encoded_events[2],
    )
    .context("decoding CbLayer2TransparentEvent")?;

    let binary_mpm = MpmReferenceValue {
        r#type: Some(mpm_reference_value::Type::Versions(MpmVersionIds {
            versions: layer2.packages.iter().map(|p| p.mpm_version_id.clone()).collect(),
        })),
    };
    let layer2_ref_values = CbLayer2TransparentReferenceValues { binary_mpm: Some(binary_mpm) };

    Ok((stage0_ref_values, layer1_ref_values, layer2_ref_values))
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
        // TODO: b/484977728 - generalizing quote fetching for quotes that are not
        // in `Evidence` under the USER_DATA_PAYLOAD_ID tag.
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
        // Here we assume that the public key in the attestation results is in DER
        // format.
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
