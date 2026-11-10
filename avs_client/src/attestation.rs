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

use std::sync::Arc;

use async_trait::async_trait;
use coset::{
    iana, sig_structure_data, CborSerializable, CoseSign1, HeaderBuilder, ProtectedHeader,
    SignatureContext,
};
use oak_proto_rust::oak::session::v1::EndorsedEvidence;
use oak_proto_rust::oak::Variant;
use oak_sdk_containers::{
    default_orchestrator_channel, InstanceSigner, OrchestratorClient, Signer,
};
use tca_common::CertificateError;
use tokio::sync::Mutex;

#[async_trait]
pub trait OrchestratorClientTrait: Send + Sync {
    async fn get_endorsed_evidence(&mut self) -> Result<EndorsedEvidence, CertificateError>;
}

#[async_trait]
impl OrchestratorClientTrait for OrchestratorClient {
    async fn get_endorsed_evidence(&mut self) -> Result<EndorsedEvidence, CertificateError> {
        self.get_endorsed_evidence()
            .await
            .map_err(|e| CertificateError::Platform(format!("Failed to get evidence: {e}")))
    }
}

#[async_trait]
pub trait AvsAttestationProvider: Send + Sync {
    /// Generates Oak Containers `EndorsedEvidence` with
    /// `Evidence.signed_user_data_certificate` cryptographically binding
    /// the server-provided `nonce` and CSR `public_key_spki_der`.
    async fn get_endorsed_evidence(
        &self,
        nonce: &[u8],
        public_key_spki_der: &[u8],
    ) -> Result<EndorsedEvidence, CertificateError>;
}

/// Encodes `(nonce, public_key_spki_der)` using the length-prefixed format
/// expected by AVS: `[4-byte big-endian len(nonce)][nonce][4-byte big-endian
/// len(public_key)][public_key]`.
pub fn encode_bound_user_data(
    nonce: &[u8],
    public_key_spki_der: &[u8],
) -> Result<Vec<u8>, CertificateError> {
    let nonce_len = u32::try_from(nonce.len())
        .map_err(|_| CertificateError::Protocol("Nonce length overflows u32".to_string()))?;
    let key_len = u32::try_from(public_key_spki_der.len())
        .map_err(|_| CertificateError::Protocol("Public key length overflows u32".to_string()))?;

    let mut payload = Vec::with_capacity(4 + nonce.len() + 4 + public_key_spki_der.len());
    payload.extend_from_slice(&nonce_len.to_be_bytes());
    payload.extend_from_slice(nonce);
    payload.extend_from_slice(&key_len.to_be_bytes());
    payload.extend_from_slice(public_key_spki_der);
    Ok(payload)
}

#[derive(Clone)]
pub struct OakAvsAttestationProvider {
    signer: Arc<dyn Signer + Send + Sync>,
    client: Arc<Mutex<dyn OrchestratorClientTrait + Send + Sync>>,
}

impl OakAvsAttestationProvider {
    pub fn new(
        signer: Arc<dyn Signer + Send + Sync>,
        client: Arc<Mutex<dyn OrchestratorClientTrait + Send + Sync>>,
    ) -> Self {
        Self { signer, client }
    }

    pub async fn create_default() -> Result<Self, CertificateError> {
        let channel = default_orchestrator_channel().await.map_err(|e| {
            CertificateError::Platform(format!("Failed to create orchestrator channel: {e}"))
        })?;
        let signer = Arc::new(InstanceSigner::create(&channel));
        let client = Arc::new(Mutex::new(OrchestratorClient::create(&channel)));
        Ok(Self { signer, client })
    }

    /// Creates a serialized `COSE_Sign1` structure over `payload` signed by the
    /// Oak Containers instance signing key via the Orchestrator's `Sign` RPC.
    pub async fn create_signed_user_data_certificate(
        &self,
        payload: &[u8],
    ) -> Result<Vec<u8>, CertificateError> {
        let protected = ProtectedHeader {
            original_data: None,
            header: HeaderBuilder::new().algorithm(iana::Algorithm::ES256).build(),
        };
        let unprotected = HeaderBuilder::new().key_id(b"AsymmetricECDSA256".to_vec()).build();

        let to_be_signed =
            sig_structure_data(SignatureContext::CoseSign1, protected.clone(), None, &[], payload);

        let oak_signature =
            self.signer.sign(&to_be_signed).await.map_err(|e| {
                CertificateError::Platform(format!("Failed to sign user data: {e:?}"))
            })?;

        let cose_sign1 = CoseSign1 {
            protected,
            unprotected,
            payload: Some(payload.to_vec()),
            signature: oak_signature.signature,
        };

        cose_sign1.to_vec().map_err(|e| {
            CertificateError::Platform(format!("Failed to serialize COSE_Sign1 user data: {e}"))
        })
    }
}

#[async_trait]
impl AvsAttestationProvider for OakAvsAttestationProvider {
    async fn get_endorsed_evidence(
        &self,
        nonce: &[u8],
        public_key_spki_der: &[u8],
    ) -> Result<EndorsedEvidence, CertificateError> {
        let payload = encode_bound_user_data(nonce, public_key_spki_der)?;
        let signed_user_data_certificate =
            self.create_signed_user_data_certificate(&payload).await?;

        let mut endorsed_evidence = {
            let mut client = self.client.lock().await;
            client.get_endorsed_evidence().await?
        };

        let evidence = endorsed_evidence.evidence.as_mut().ok_or_else(|| {
            CertificateError::Platform("Missing evidence from orchestrator".to_string())
        })?;
        evidence.signed_user_data_certificate = signed_user_data_certificate;

        let endorsements = endorsed_evidence.endorsements.as_mut().ok_or_else(|| {
            CertificateError::Platform("Missing endorsements from orchestrator".to_string())
        })?;
        if endorsements.initial.is_none() {
            endorsements.initial = Some(Variant::default());
        }

        Ok(endorsed_evidence)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use oak_attestation_verification::{
        results::get_user_data_payload, verifier::verify_user_data_certificate,
    };
    use oak_proto_rust::oak::attestation::v1::{Endorsements, Evidence};
    use oak_proto_rust::oak::crypto::v1::Signature as OakSignature;
    use p256::ecdsa::{signature::Signer as EcdsaSigner, Signature as P256Signature, SigningKey};

    struct MockSigner {
        signing_key: SigningKey,
    }

    #[async_trait]
    impl Signer for MockSigner {
        async fn sign(&self, data: &[u8]) -> anyhow::Result<OakSignature> {
            let sig: P256Signature = self.signing_key.sign(data);
            Ok(OakSignature { signature: sig.to_bytes().to_vec() })
        }
    }

    struct MockOrchestrator {
        evidence: EndorsedEvidence,
    }

    #[async_trait]
    impl OrchestratorClientTrait for MockOrchestrator {
        async fn get_endorsed_evidence(&mut self) -> Result<EndorsedEvidence, CertificateError> {
            Ok(self.evidence.clone())
        }
    }

    #[tokio::test]
    async fn test_oak_avs_attestation_provider_binds_nonce_and_key_verifiable_by_oak() {
        let signing_key = SigningKey::from_bytes((&[0x42u8; 32]).into()).unwrap();
        let verifying_key = *signing_key.verifying_key();

        let provider = OakAvsAttestationProvider::new(
            Arc::new(MockSigner { signing_key }),
            Arc::new(Mutex::new(MockOrchestrator {
                evidence: EndorsedEvidence {
                    evidence: Some(Evidence::default()),
                    endorsements: Some(Endorsements::default()),
                },
            })),
        );

        let nonce = b"challenge-nonce-12345";
        let spki = b"subject-public-key-info-der";
        let endorsed = provider.get_endorsed_evidence(nonce, spki).await.unwrap();
        let evidence = endorsed.evidence.unwrap();

        let event_result =
            verify_user_data_certificate(&evidence.signed_user_data_certificate, &verifying_key)
                .expect("COSE_Sign1 user data certificate must verify");
        let extracted_payload =
            get_user_data_payload(&event_result).expect("payload artifact must be set");
        assert_eq!(extracted_payload.as_slice(), encode_bound_user_data(nonce, spki).unwrap());
    }
}
