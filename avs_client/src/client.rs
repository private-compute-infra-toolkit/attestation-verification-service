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

use async_trait::async_trait;
use avs_client_proto_rust::avs::{CertificateProfile, CertificationParameters, OperatorInfo};
use tca_common::{Certificate, CertificateChain, CertificateError, Csr};

use crate::attestation::{AvsAttestationProvider, OakAvsAttestationProvider};
use crate::transport::{AvsTransport, TonicAvsTransport};

#[derive(Debug, Clone, PartialEq, Default)]
pub struct AvsCertifyOptions {
    pub operator_info: Option<OperatorInfo>,
    pub certification_parameters: Option<CertificationParameters>,
}

impl AvsCertifyOptions {
    /// Creates options selecting a policy by `policy_name` and
    /// `certificate_profile`.
    pub fn new(policy_name: impl Into<String>, certificate_profile: CertificateProfile) -> Self {
        Self::from_certification_parameters(CertificationParameters {
            policy_name: policy_name.into(),
            certificate_profile: certificate_profile.into(),
        })
    }

    /// Creates options with explicit `CertificationParameters`.
    pub fn from_certification_parameters(params: CertificationParameters) -> Self {
        Self { operator_info: None, certification_parameters: Some(params) }
    }

    /// Sets the `OperatorInfo` (`operator_domain` and `operator_role`).
    pub fn with_operator_info(mut self, operator_info: OperatorInfo) -> Self {
        self.operator_info = Some(operator_info);
        self
    }

    /// Sets `operator_domain` and `operator_role`.
    pub fn with_operator_domain_and_role(
        mut self,
        operator_domain: impl Into<String>,
        operator_role: impl Into<String>,
    ) -> Self {
        self.operator_info = Some(OperatorInfo {
            operator_domain: operator_domain.into(),
            operator_role: operator_role.into(),
        });
        self
    }

    /// Sets `operator_role` (leaving `operator_domain` unchanged if already
    /// set, or empty so the host proxy / AVS host can populate it).
    pub fn with_operator_role(mut self, operator_role: impl Into<String>) -> Self {
        let operator_domain = self
            .operator_info
            .as_ref()
            .map(|info| info.operator_domain.clone())
            .unwrap_or_default();
        self.operator_info =
            Some(OperatorInfo { operator_domain, operator_role: operator_role.into() });
        self
    }

    /// Sets `CertificationParameters` (`policy_name` and
    /// `certificate_profile`).
    pub fn with_certification_parameters(
        mut self,
        policy_name: impl Into<String>,
        certificate_profile: CertificateProfile,
    ) -> Self {
        self.certification_parameters = Some(CertificationParameters {
            policy_name: policy_name.into(),
            certificate_profile: certificate_profile.into(),
        });
        self
    }
}

#[async_trait]
pub trait AvsClient: Send + Sync {
    /// Certifies the workload's attestation evidence and issues an X.509
    /// certificate chain for the given `csr` and `options`.
    async fn certify_attestation(
        &self,
        csr: Csr,
        options: AvsCertifyOptions,
    ) -> Result<CertificateChain, CertificateError>;
}

#[derive(Debug, Clone)]
pub struct StandardAvsClient<P, T> {
    provider: P,
    transport: T,
}

impl<P, T> StandardAvsClient<P, T> {
    pub fn new(provider: P, transport: T) -> Self {
        Self { provider, transport }
    }
}

#[async_trait]
impl<P: AvsAttestationProvider + Send + Sync, T: AvsTransport + Send + Sync> AvsClient
    for StandardAvsClient<P, T>
{
    async fn certify_attestation(
        &self,
        csr: Csr,
        options: AvsCertifyOptions,
    ) -> Result<CertificateChain, CertificateError> {
        let public_key_spki_der = csr.public_key()?;
        let response = self
            .transport
            .certify_attestation_stream(csr, public_key_spki_der, options, &self.provider)
            .await?;
        let certs = response.certificate_chain.into_iter().map(Certificate).collect();
        Ok(CertificateChain(certs))
    }
}

#[derive(Debug, Clone)]
pub struct OakAvsClient<P = OakAvsAttestationProvider, T = TonicAvsTransport> {
    inner: StandardAvsClient<P, T>,
}

impl OakAvsClient<OakAvsAttestationProvider, TonicAvsTransport> {
    pub async fn create(endpoint: impl Into<String>) -> Result<Self, CertificateError> {
        Ok(Self {
            inner: StandardAvsClient::new(
                OakAvsAttestationProvider::create_default().await?,
                TonicAvsTransport::new(endpoint.into()),
            ),
        })
    }
}

impl<P: AvsAttestationProvider, T: AvsTransport> OakAvsClient<P, T> {
    pub fn with_transport(provider: P, transport: T) -> Self {
        Self { inner: StandardAvsClient::new(provider, transport) }
    }
}

#[async_trait]
impl<P: AvsAttestationProvider + Send + Sync, T: AvsTransport + Send + Sync> AvsClient
    for OakAvsClient<P, T>
{
    async fn certify_attestation(
        &self,
        csr: Csr,
        options: AvsCertifyOptions,
    ) -> Result<CertificateChain, CertificateError> {
        self.inner.certify_attestation(csr, options).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};
    use std::sync::Arc;

    use avs_client_proto_rust::avs::{
        attestation_verification_server::{AttestationVerification, AttestationVerificationServer},
        certify_attestation_request, certify_attestation_stream_request,
        certify_attestation_stream_response, CertifyAttestationRequest, CertifyAttestationResponse,
        CertifyAttestationStreamRequest, CertifyAttestationStreamResponse, ChallengeResponse,
        GenerateAvsSigningKeyRequest, GenerateAvsSigningKeyResponse,
    };
    use oak_attestation_verification::{
        results::get_user_data_payload, verifier::verify_user_data_certificate,
    };
    use oak_proto_rust::oak::attestation::v1::{Endorsements, Evidence};
    use oak_proto_rust::oak::crypto::v1::Signature as OakSignature;
    use oak_proto_rust::oak::session::v1::EndorsedEvidence;
    use oak_sdk_containers::Signer;
    use p256::ecdsa::{
        signature::Signer as EcdsaSigner, Signature as P256Signature, SigningKey, VerifyingKey,
    };
    use tokio::net::TcpListener;
    use tokio::sync::{mpsc, Mutex};
    use tokio_stream::{wrappers::ReceiverStream, StreamExt};
    use tonic::{Request, Response, Status, Streaming};

    use crate::attestation::{encode_bound_user_data, OrchestratorClientTrait};

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

    struct MockAvsServer {
        expected_verifying_key: VerifyingKey,
        expected_nonce: Vec<u8>,
    }

    #[tonic::async_trait]
    impl AttestationVerification for MockAvsServer {
        async fn certify_attestation(
            &self,
            _request: Request<CertifyAttestationRequest>,
        ) -> Result<Response<CertifyAttestationResponse>, Status> {
            Err(Status::unimplemented("Use CertifyAttestationStream"))
        }

        type CertifyAttestationStreamStream =
            ReceiverStream<Result<CertifyAttestationStreamResponse, Status>>;

        async fn certify_attestation_stream(
            &self,
            request: Request<Streaming<CertifyAttestationStreamRequest>>,
        ) -> Result<Response<Self::CertifyAttestationStreamStream>, Status> {
            let mut in_stream = request.into_inner();
            let (tx, rx) = mpsc::channel(2);
            let expected_vk = self.expected_verifying_key;
            let expected_nonce = self.expected_nonce.clone();

            tokio::spawn(async move {
                // 1. Expect ChallengeRequest
                let first = in_stream.next().await.unwrap().unwrap();
                assert!(matches!(
                    first.request,
                    Some(certify_attestation_stream_request::Request::ChallengeRequest(_))
                ));

                // 2. Send ChallengeResponse
                tx.send(Ok(CertifyAttestationStreamResponse {
                    response: Some(
                        certify_attestation_stream_response::Response::ChallengeResponse(
                            ChallengeResponse { nonce: expected_nonce.clone() },
                        ),
                    ),
                }))
                .await
                .unwrap();

                // 3. Verify CertifyRequest and COSE_Sign1 user data binding
                let second = in_stream.next().await.unwrap().unwrap();
                let Some(certify_attestation_stream_request::Request::CertifyRequest(certify_req)) =
                    second.request
                else {
                    panic!("Expected CertifyRequest");
                };

                assert_eq!(
                    certify_req.operator_info,
                    Some(OperatorInfo {
                        operator_domain: "prod.google.com".to_string(),
                        operator_role: "dev".to_string(),
                    })
                );
                assert_eq!(
                    certify_req.selector,
                    Some(certify_attestation_request::Selector::CertificationParameters(
                        CertificationParameters {
                            policy_name: "development".to_string(),
                            certificate_profile: CertificateProfile::Mtls.into(),
                        }
                    ))
                );

                let csr_spki = Csr(certify_req.csr.clone()).public_key().unwrap();
                let expected_payload = encode_bound_user_data(&expected_nonce, &csr_spki).unwrap();
                let evidence = certify_req.evidence.unwrap();
                let event_result = verify_user_data_certificate(
                    &evidence.signed_user_data_certificate,
                    &expected_vk,
                )
                .expect("COSE_Sign1 signature must verify");
                assert_eq!(
                    get_user_data_payload(&event_result).unwrap().as_slice(),
                    expected_payload.as_slice()
                );

                // 4. Send CertifyAttestationResponse
                tx.send(Ok(CertifyAttestationStreamResponse {
                    response: Some(certify_attestation_stream_response::Response::CertifyResponse(
                        CertifyAttestationResponse {
                            certificate_chain: vec![
                                b"leaf-cert-der".to_vec(),
                                b"ca-cert-der".to_vec(),
                            ],
                            tlog_verification_results: vec![],
                        },
                    )),
                }))
                .await
                .unwrap();
            });

            Ok(Response::new(ReceiverStream::new(rx)))
        }

        async fn generate_avs_signing_key(
            &self,
            _request: Request<GenerateAvsSigningKeyRequest>,
        ) -> Result<Response<GenerateAvsSigningKeyResponse>, Status> {
            Err(Status::unimplemented("Not needed in MockAvsServer"))
        }
    }

    fn generate_test_csr(subject: &str) -> (Vec<u8>, rcgen::KeyPair) {
        let key_pair = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).unwrap();
        let mut params = rcgen::CertificateParams::new(vec![]).unwrap();
        params.distinguished_name.push(rcgen::DnType::CommonName, subject);
        let csr = params.serialize_request(&key_pair).unwrap();
        (csr.der().to_vec(), key_pair)
    }

    #[tokio::test]
    async fn test_oak_avs_client_stream_handshake_with_mock_server() {
        let signing_key = SigningKey::from_bytes((&[0x42u8; 32]).into()).unwrap();
        let verifying_key = *signing_key.verifying_key();

        let listener =
            TcpListener::bind(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0)).await.unwrap();
        let port = listener.local_addr().unwrap().port();

        let mock_server = MockAvsServer {
            expected_verifying_key: verifying_key,
            expected_nonce: b"server-challenge-nonce-32-bytes!".to_vec(),
        };
        tokio::spawn(async move {
            tonic::transport::Server::builder()
                .add_service(AttestationVerificationServer::new(mock_server))
                .serve_with_incoming(tokio_stream::wrappers::TcpListenerStream::new(listener))
                .await
                .unwrap();
        });

        let provider = OakAvsAttestationProvider::new(
            Arc::new(MockSigner { signing_key }),
            Arc::new(Mutex::new(MockOrchestrator {
                evidence: EndorsedEvidence {
                    evidence: Some(Evidence::default()),
                    endorsements: Some(Endorsements::default()),
                },
            })),
        );
        let transport = TonicAvsTransport::new(format!("http://127.0.0.1:{port}"));
        let client = OakAvsClient::with_transport(provider, transport);

        let (csr_der, _key_pair) = generate_test_csr("oak-workload.example.com");
        let options = AvsCertifyOptions::new("development", CertificateProfile::Mtls)
            .with_operator_domain_and_role("prod.google.com", "dev");

        let chain = client.certify_attestation(Csr(csr_der), options).await.unwrap();
        assert_eq!(chain.0.len(), 2);
        assert_eq!(chain.0[0], Certificate(b"leaf-cert-der".to_vec()));
        assert_eq!(chain.0[1], Certificate(b"ca-cert-der".to_vec()));
    }

    #[test]
    fn test_avs_certify_options_builders() {
        let default_opts = AvsCertifyOptions::default();
        assert_eq!(default_opts.operator_info, None);
        assert_eq!(default_opts.certification_parameters, None);

        let role_only = AvsCertifyOptions::default()
            .with_operator_role("enclave-role")
            .with_certification_parameters("encrypted_zone", CertificateProfile::Tls);
        assert_eq!(
            role_only.operator_info,
            Some(OperatorInfo {
                operator_domain: String::new(),
                operator_role: "enclave-role".to_string(),
            })
        );
        assert_eq!(
            role_only.certification_parameters,
            Some(CertificationParameters {
                policy_name: "encrypted_zone".to_string(),
                certificate_profile: CertificateProfile::Tls.into(),
            })
        );

        let updated_role = AvsCertifyOptions::default()
            .with_operator_info(OperatorInfo {
                operator_domain: "prod.google.com".to_string(),
                operator_role: "initial".to_string(),
            })
            .with_operator_role("updated");
        assert_eq!(
            updated_role.operator_info,
            Some(OperatorInfo {
                operator_domain: "prod.google.com".to_string(),
                operator_role: "updated".to_string(),
            })
        );
    }
}
