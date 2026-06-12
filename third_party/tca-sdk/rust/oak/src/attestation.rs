// Copyright 2026 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

use async_trait::async_trait;
use oak_proto_rust::oak::crypto::v1::Signature;
use oak_proto_rust::oak::session::v1::EndorsedEvidence;
use oak_sdk_containers::{
    default_orchestrator_channel, InstanceSigner, OrchestratorClient, Signer,
};
use prost::Message;
use tca_common::requirements::AttestationProvider;
use tca_common::CertificateError;
use trusted_certificate_authority_proto::google::tca::v1::{
    attestation_evidence::Evidence, AttestationEvidence, OakAttestationEvidence,
};

use std::sync::Arc;

#[async_trait]
pub trait OrchestratorClientTrait: Send + Sync {
    async fn get_endorsed_evidence(&mut self) -> Result<EndorsedEvidence, CertificateError>;
}

#[async_trait::async_trait]
impl OrchestratorClientTrait for OrchestratorClient {
    async fn get_endorsed_evidence(&mut self) -> Result<EndorsedEvidence, CertificateError> {
        self.get_endorsed_evidence()
            .await
            .map_err(|e| CertificateError::Platform(format!("Failed to get evidence: {}", e)))
    }
}

use tokio::sync::Mutex;

#[derive(Clone)]
pub struct OakAttestationProvider {
    signer: Arc<dyn Signer + Send + Sync>,
    client: Arc<Mutex<dyn OrchestratorClientTrait + Send + Sync>>,
}

impl OakAttestationProvider {
    pub fn new(
        signer: Arc<dyn Signer + Send + Sync>,
        client: Arc<Mutex<dyn OrchestratorClientTrait + Send + Sync>>,
    ) -> Self {
        Self { signer, client }
    }

    pub async fn create_default() -> Result<Self, CertificateError> {
        let channel = default_orchestrator_channel().await.map_err(|e| {
            CertificateError::Platform(format!("Failed to create orchestrator channel: {}", e))
        })?;
        let signer = Arc::new(InstanceSigner::create(&channel));
        let client = Arc::new(Mutex::new(OrchestratorClient::create(&channel)));
        Ok(Self { signer, client })
    }
}

#[async_trait]
impl AttestationProvider for OakAttestationProvider {
    async fn get_evidence(
        &self,
        binding_data: &[u8],
    ) -> Result<AttestationEvidence, CertificateError> {
        let signature = self
            .signer
            .sign(binding_data)
            .await
            .map_err(|e| CertificateError::Platform(format!("Failed to sign data: {:?}", e)))?;

        let evidence = {
            let mut client = self.client.lock().await;
            client.get_endorsed_evidence().await?
        };

        Self::convert_to_proto(evidence, signature)
    }
}

impl OakAttestationProvider {
    pub(crate) fn convert_to_proto(
        evidence: EndorsedEvidence,
        signature: Signature,
    ) -> Result<AttestationEvidence, CertificateError> {
        let evidence_bytes = evidence
            .evidence
            .as_ref()
            .ok_or_else(|| CertificateError::Platform("Missing evidence".to_string()))?
            .encode_to_vec();

        let endorsements_bytes = evidence
            .endorsements
            .as_ref()
            .ok_or_else(|| CertificateError::Platform("Missing endorsements".to_string()))?
            .encode_to_vec();

        let oak_evidence = OakAttestationEvidence {
            evidence: Some(Message::decode(evidence_bytes.as_slice()).map_err(|e| {
                CertificateError::Platform(format!("Failed to decode evidence: {}", e))
            })?),
            endorsements: Some(Message::decode(endorsements_bytes.as_slice()).map_err(|e| {
                CertificateError::Platform(format!("Failed to decode endorsements: {}", e))
            })?),
            signed_public_key: signature.signature,
        };

        Ok(AttestationEvidence { evidence: Some(Evidence::OakAttestationEvidence(oak_evidence)) })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use oak_proto_rust::oak::crypto::v1::Signature as OakSignature;
    use oak_proto_rust::oak::session::v1::EndorsedEvidence;
    use p256::ecdsa::signature::{Signer as EcdsaSigner, Verifier};
    use p256::ecdsa::{Signature as P256Signature, SigningKey};
    use trusted_certificate_authority_proto::google::tca::v1::attestation_evidence::Evidence;

    struct TestContext {
        priv_key: SigningKey,
        evidence: EndorsedEvidence,
    }

    struct MockSigner {
        context: Arc<TestContext>,
    }

    #[async_trait]
    impl Signer for MockSigner {
        async fn sign(&self, data: &[u8]) -> Result<OakSignature, anyhow::Error> {
            let signature: P256Signature = self.context.priv_key.sign(data);
            Ok(OakSignature { signature: signature.to_bytes().to_vec() })
        }
    }

    struct MockClient {
        context: Arc<TestContext>,
    }

    #[async_trait]
    impl OrchestratorClientTrait for MockClient {
        async fn get_endorsed_evidence(&mut self) -> Result<EndorsedEvidence, CertificateError> {
            Ok(self.context.evidence.clone())
        }
    }

    #[tokio::test]
    async fn test_get_evidence_cryptographic_binding() {
        let mut rng = rand::rngs::OsRng;
        let priv_key = SigningKey::random(&mut rng);
        let pub_key = priv_key.verifying_key();

        use oak_proto_rust::oak::attestation::v1::{Evidence as OakEvidenceProto, LayerEvidence};

        let mock_evidence = EndorsedEvidence {
            evidence: Some(OakEvidenceProto {
                layers: vec![LayerEvidence { eca_certificate: b"test_cert_forwarding".to_vec() }],
                ..Default::default()
            }),
            endorsements: Some(Default::default()),
        };

        let context = Arc::new(TestContext { priv_key: priv_key.clone(), evidence: mock_evidence });

        let signer = Arc::new(MockSigner { context: context.clone() });
        let client = Arc::new(Mutex::new(MockClient { context: context.clone() }));

        let provider = OakAttestationProvider::new(signer, client);
        let binding_data = b"csr_pubkey";

        let result = provider.get_evidence(binding_data).await.unwrap();

        if let Some(Evidence::OakAttestationEvidence(oak_evidence)) = result.evidence {
            // Verify public key binding signature
            let signature =
                P256Signature::try_from(oak_evidence.signed_public_key.as_slice()).unwrap();
            let verify_result = pub_key.verify(binding_data, &signature);
            assert!(verify_result.is_ok(), "Signature verification failed");

            // Verify evidence forwarding
            let inner_evidence = oak_evidence.evidence.as_ref().unwrap();
            assert_eq!(inner_evidence.layers.len(), 1);
            assert_eq!(inner_evidence.layers[0].eca_certificate, b"test_cert_forwarding");
        } else {
            panic!("Wrong evidence type");
        }
    }
}
