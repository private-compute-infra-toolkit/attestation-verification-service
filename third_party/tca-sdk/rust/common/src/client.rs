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

use crate::api::TcaClient;
use crate::attestation::AttestationProvider;
use crate::error::CertificateError;
use crate::transport::TcaTransport;
use crate::types::{Certificate, CertificateChain, Csr};
use async_trait::async_trait;
use trusted_certificate_authority_proto::google::tca::v1::IssueCertificateRequest;

#[derive(Debug, Clone)]
pub struct StandardTcaClient<P, T> {
    provider: P,
    transport: T,
}

impl<P, T> StandardTcaClient<P, T> {
    pub fn new(provider: P, transport: T) -> Self {
        Self { provider, transport }
    }
}

#[async_trait]
impl<P: AttestationProvider + Send + Sync, T: TcaTransport + Send + Sync> TcaClient
    for StandardTcaClient<P, T>
{
    async fn issue_certificate(&self, csr: Csr) -> Result<CertificateChain, CertificateError> {
        let public_key_bytes = csr.public_key()?;
        let evidence = self.provider.get_evidence(&public_key_bytes).await?;

        let request = IssueCertificateRequest {
            certificate_signing_request: csr.0,
            attestation_evidence: Some(evidence),
        };

        let response = self.transport.issue_certificate(request).await?;

        let certs = response.signed_certificates.into_iter().map(Certificate).collect();

        Ok(CertificateChain(certs))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rsa::pkcs1v15::{Signature as RsaSignature, SigningKey};
    use rsa::sha2::Sha256;
    use rsa::RsaPrivateKey;
    use std::str::FromStr;
    use trusted_certificate_authority_proto::google::tca::v1::{
        attestation_evidence::Evidence, AttestationEvidence, OakAttestationEvidence,
    };
    use trusted_certificate_authority_proto::google::tca::v1::{
        IssueCertificateRequest, IssueCertificateResponse,
    };
    use x509_cert::{
        builder::{Builder, RequestBuilder},
        der::Encode,
        name::Name,
    };

    struct MockProvider;

    #[async_trait]
    impl AttestationProvider for MockProvider {
        async fn get_evidence(
            &self,
            _binding_data: &[u8],
        ) -> Result<AttestationEvidence, CertificateError> {
            Ok(AttestationEvidence {
                evidence: Some(Evidence::OakAttestationEvidence(OakAttestationEvidence {
                    evidence: None,
                    endorsements: None,
                    signed_public_key: vec![],
                })),
            })
        }
    }

    struct MockTransport;

    #[async_trait]
    impl TcaTransport for MockTransport {
        async fn issue_certificate(
            &self,
            _request: IssueCertificateRequest,
        ) -> Result<IssueCertificateResponse, CertificateError> {
            Ok(IssueCertificateResponse { signed_certificates: vec![vec![0xDE, 0xAD, 0xBE, 0xEF]] })
        }
    }

    #[tokio::test]
    async fn test_standard_client_flow() {
        // 1. Generate a valid CSR
        let mut rng = rand::rngs::OsRng;
        let private_key = RsaPrivateKey::new(&mut rng, 2048).unwrap();
        let subject = Name::from_str("CN=Test").unwrap();
        let signing_key = SigningKey::<Sha256>::new(private_key);
        let builder = RequestBuilder::new(subject, &signing_key).unwrap();
        let csr = builder.build::<RsaSignature>().unwrap();
        let csr_der = csr.to_der().unwrap();

        // 2. Create client with MockProvider and MockTransport
        let client = StandardTcaClient::new(MockProvider, MockTransport);

        // 3. Call issue_certificate
        let result = client.issue_certificate(Csr(csr_der)).await;

        // 4. Verify result
        assert!(result.is_ok());
        let chain = result.unwrap();
        assert_eq!(chain.0.len(), 1);
        assert_eq!(chain.0[0].0, vec![0xDE, 0xAD, 0xBE, 0xEF]);
    }
}
