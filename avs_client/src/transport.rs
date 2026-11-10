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
use avs_client_proto_rust::avs::{
    attestation_verification_client::AttestationVerificationClient, certify_attestation_request,
    certify_attestation_stream_request, certify_attestation_stream_response,
    CertifyAttestationRequest, CertifyAttestationResponse, CertifyAttestationStreamRequest,
    ChallengeRequest,
};
use tca_common::{CertificateError, Csr};
use tokio::sync::mpsc;
use tokio_stream::{wrappers::ReceiverStream, StreamExt};

use crate::attestation::AvsAttestationProvider;
use crate::client::AvsCertifyOptions;

#[async_trait]
pub trait AvsTransport: Send + Sync {
    async fn certify_attestation_stream<P: AvsAttestationProvider + ?Sized>(
        &self,
        csr: Csr,
        public_key_spki_der: Vec<u8>,
        options: AvsCertifyOptions,
        provider: &P,
    ) -> Result<CertifyAttestationResponse, CertificateError>;
}

#[derive(Debug, Clone)]
pub struct TonicAvsTransport {
    endpoint: String,
}

impl TonicAvsTransport {
    pub fn new(endpoint: impl Into<String>) -> Self {
        Self { endpoint: endpoint.into() }
    }
}

#[async_trait]
impl AvsTransport for TonicAvsTransport {
    async fn certify_attestation_stream<P: AvsAttestationProvider + ?Sized>(
        &self,
        csr: Csr,
        public_key_spki_der: Vec<u8>,
        options: AvsCertifyOptions,
        provider: &P,
    ) -> Result<CertifyAttestationResponse, CertificateError> {
        let mut client = AttestationVerificationClient::connect(self.endpoint.clone())
            .await
            .map_err(|e| CertificateError::Network(format!("Failed to connect to AVS: {e}")))?;

        let (tx, rx) = mpsc::channel(2);

        tx.send(CertifyAttestationStreamRequest {
            request: Some(certify_attestation_stream_request::Request::ChallengeRequest(
                ChallengeRequest {},
            )),
        })
        .await
        .map_err(|e| {
            CertificateError::Network(format!("Failed to enqueue AVS challenge request: {e}"))
        })?;

        let mut response_stream = client
            .certify_attestation_stream(ReceiverStream::new(rx))
            .await
            .map_err(|e| {
                CertificateError::Network(format!("AVS CertifyAttestationStream failed: {e}"))
            })?
            .into_inner();

        // Step 1: Receive ChallengeResponse containing the server nonce.
        let challenge_msg = response_stream
            .next()
            .await
            .ok_or_else(|| {
                CertificateError::Protocol(
                    "AVS stream closed before ChallengeResponse was received".to_string(),
                )
            })?
            .map_err(|e| {
                CertificateError::Network(format!("Error reading AVS ChallengeResponse: {e}"))
            })?;

        let nonce = match challenge_msg.response {
            Some(certify_attestation_stream_response::Response::ChallengeResponse(challenge)) => {
                challenge.nonce
            }
            other => {
                return Err(CertificateError::Protocol(format!(
                    "Expected ChallengeResponse from AVS, got: {other:?}"
                )));
            }
        };

        // Step 2: Bind (nonce, public_key_spki_der) into
        // Evidence.signed_user_data_certificate.
        let endorsed_evidence =
            provider.get_endorsed_evidence(&nonce, &public_key_spki_der).await?;

        if endorsed_evidence.evidence.is_none() {
            return Err(CertificateError::Platform("Missing evidence".to_string()));
        }
        if endorsed_evidence.endorsements.is_none() {
            return Err(CertificateError::Platform("Missing endorsements".to_string()));
        }

        let certify_request = CertifyAttestationRequest {
            csr: csr.0,
            evidence: endorsed_evidence.evidence,
            endorsements: endorsed_evidence.endorsements,
            operator_info: options.operator_info,
            selector: options
                .certification_parameters
                .map(certify_attestation_request::Selector::CertificationParameters),
        };

        tx.send(CertifyAttestationStreamRequest {
            request: Some(certify_attestation_stream_request::Request::CertifyRequest(
                certify_request,
            )),
        })
        .await
        .map_err(|e| {
            CertificateError::Network(format!("Failed to send AVS CertifyAttestationRequest: {e}"))
        })?;
        // Half-close the outbound stream now that the single CertifyRequest
        // has been sent.
        drop(tx);

        // Step 3: Receive CertifyAttestationResponse.
        let certify_msg = response_stream
            .next()
            .await
            .ok_or_else(|| {
                CertificateError::Protocol(
                    "AVS stream closed before CertifyAttestationResponse was received".to_string(),
                )
            })?
            .map_err(|e| {
                CertificateError::Network(format!(
                    "Error reading AVS CertifyAttestationResponse: {e}"
                ))
            })?;

        match certify_msg.response {
            Some(certify_attestation_stream_response::Response::CertifyResponse(resp)) => Ok(resp),
            other => Err(CertificateError::Protocol(format!(
                "Expected CertifyAttestationResponse from AVS, got: {other:?}"
            ))),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};

    use avs_client_proto_rust::avs::{
        attestation_verification_server::{AttestationVerification, AttestationVerificationServer},
        CertifyAttestationStreamResponse, ChallengeResponse, GenerateAvsSigningKeyRequest,
        GenerateAvsSigningKeyResponse,
    };
    use oak_proto_rust::oak::attestation::v1::{Endorsements, Evidence};
    use oak_proto_rust::oak::session::v1::EndorsedEvidence;
    use tokio::net::TcpListener;
    use tonic::{Request, Response, Status, Streaming};

    struct StaticProvider {
        evidence: EndorsedEvidence,
    }

    #[async_trait]
    impl AvsAttestationProvider for StaticProvider {
        async fn get_endorsed_evidence(
            &self,
            _nonce: &[u8],
            _public_key_spki_der: &[u8],
        ) -> Result<EndorsedEvidence, CertificateError> {
            Ok(self.evidence.clone())
        }
    }

    #[derive(Clone, Copy)]
    enum ServerBehavior {
        CloseImmediately,
        WrongFirstResponse,
        CloseAfterChallenge,
        WrongSecondResponse,
    }

    struct FaultyAvsServer {
        behavior: ServerBehavior,
    }

    #[tonic::async_trait]
    impl AttestationVerification for FaultyAvsServer {
        async fn certify_attestation(
            &self,
            _request: Request<CertifyAttestationRequest>,
        ) -> Result<Response<CertifyAttestationResponse>, Status> {
            Err(Status::unimplemented("unused"))
        }

        type CertifyAttestationStreamStream =
            ReceiverStream<Result<CertifyAttestationStreamResponse, Status>>;

        async fn certify_attestation_stream(
            &self,
            request: Request<Streaming<CertifyAttestationStreamRequest>>,
        ) -> Result<Response<Self::CertifyAttestationStreamStream>, Status> {
            let mut in_stream = request.into_inner();
            let (tx, rx) = mpsc::channel(2);
            let behavior = self.behavior;

            tokio::spawn(async move {
                let _ = in_stream.next().await;
                match behavior {
                    ServerBehavior::CloseImmediately => {}
                    ServerBehavior::WrongFirstResponse => {
                        let _ = tx
                            .send(Ok(CertifyAttestationStreamResponse {
                                response: Some(
                                    certify_attestation_stream_response::Response::CertifyResponse(
                                        CertifyAttestationResponse::default(),
                                    ),
                                ),
                            }))
                            .await;
                    }
                    ServerBehavior::CloseAfterChallenge => {
                        let _ = tx
                            .send(Ok(CertifyAttestationStreamResponse {
                                response: Some(
                                    certify_attestation_stream_response::Response::ChallengeResponse(
                                        ChallengeResponse { nonce: b"nonce".to_vec() },
                                    ),
                                ),
                            }))
                            .await;
                        let _ = in_stream.next().await;
                    }
                    ServerBehavior::WrongSecondResponse => {
                        let _ = tx
                            .send(Ok(CertifyAttestationStreamResponse {
                                response: Some(
                                    certify_attestation_stream_response::Response::ChallengeResponse(
                                        ChallengeResponse { nonce: b"nonce".to_vec() },
                                    ),
                                ),
                            }))
                            .await;
                        let _ = in_stream.next().await;
                        let _ = tx
                            .send(Ok(CertifyAttestationStreamResponse {
                                response: Some(
                                    certify_attestation_stream_response::Response::ChallengeResponse(
                                        ChallengeResponse { nonce: b"nonce2".to_vec() },
                                    ),
                                ),
                            }))
                            .await;
                    }
                }
            });

            Ok(Response::new(ReceiverStream::new(rx)))
        }

        async fn generate_avs_signing_key(
            &self,
            _request: Request<GenerateAvsSigningKeyRequest>,
        ) -> Result<Response<GenerateAvsSigningKeyResponse>, Status> {
            Err(Status::unimplemented("unused"))
        }
    }

    async fn spawn_faulty_server(behavior: ServerBehavior) -> String {
        let listener =
            TcpListener::bind(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0)).await.unwrap();
        let port = listener.local_addr().unwrap().port();
        tokio::spawn(async move {
            tonic::transport::Server::builder()
                .add_service(AttestationVerificationServer::new(FaultyAvsServer { behavior }))
                .serve_with_incoming(tokio_stream::wrappers::TcpListenerStream::new(listener))
                .await
                .unwrap();
        });
        format!("http://127.0.0.1:{port}")
    }

    #[tokio::test]
    async fn test_tonic_transport_error_paths() {
        let valid_provider = StaticProvider {
            evidence: EndorsedEvidence {
                evidence: Some(Evidence::default()),
                endorsements: Some(Endorsements::default()),
            },
        };

        // 1. Connection failure
        let bad_transport = TonicAvsTransport::new("http://127.0.0.1:1");
        assert!(matches!(
            bad_transport
                .certify_attestation_stream(
                    Csr(vec![]),
                    vec![],
                    AvsCertifyOptions::default(),
                    &valid_provider
                )
                .await,
            Err(CertificateError::Network(_))
        ));

        // 2. Stream closed before ChallengeResponse
        let endpoint = spawn_faulty_server(ServerBehavior::CloseImmediately).await;
        let transport = TonicAvsTransport::new(endpoint);
        assert!(matches!(
            transport
                .certify_attestation_stream(
                    Csr(vec![]),
                    vec![],
                    AvsCertifyOptions::default(),
                    &valid_provider
                )
                .await,
            Err(CertificateError::Protocol(_))
        ));

        // 3. Unexpected first response
        let endpoint = spawn_faulty_server(ServerBehavior::WrongFirstResponse).await;
        let transport = TonicAvsTransport::new(endpoint);
        assert!(matches!(
            transport
                .certify_attestation_stream(
                    Csr(vec![]),
                    vec![],
                    AvsCertifyOptions::default(),
                    &valid_provider
                )
                .await,
            Err(CertificateError::Protocol(_))
        ));

        // 4. Missing evidence or endorsements from provider
        let endpoint = spawn_faulty_server(ServerBehavior::CloseAfterChallenge).await;
        let transport = TonicAvsTransport::new(endpoint.clone());
        let no_evidence_provider = StaticProvider {
            evidence: EndorsedEvidence {
                evidence: None,
                endorsements: Some(Endorsements::default()),
            },
        };
        assert!(matches!(
            transport
                .certify_attestation_stream(
                    Csr(vec![]),
                    vec![],
                    AvsCertifyOptions::default(),
                    &no_evidence_provider
                )
                .await,
            Err(CertificateError::Platform(_))
        ));
        let no_endorsements_provider = StaticProvider {
            evidence: EndorsedEvidence { evidence: Some(Evidence::default()), endorsements: None },
        };
        assert!(matches!(
            transport
                .certify_attestation_stream(
                    Csr(vec![]),
                    vec![],
                    AvsCertifyOptions::default(),
                    &no_endorsements_provider
                )
                .await,
            Err(CertificateError::Platform(_))
        ));

        // 5. Stream closed after ChallengeResponse before CertifyResponse
        assert!(matches!(
            transport
                .certify_attestation_stream(
                    Csr(vec![]),
                    vec![],
                    AvsCertifyOptions::default(),
                    &valid_provider
                )
                .await,
            Err(CertificateError::Protocol(_))
        ));

        // 6. Unexpected second response
        let endpoint = spawn_faulty_server(ServerBehavior::WrongSecondResponse).await;
        let transport = TonicAvsTransport::new(endpoint);
        assert!(matches!(
            transport
                .certify_attestation_stream(
                    Csr(vec![]),
                    vec![],
                    AvsCertifyOptions::default(),
                    &valid_provider
                )
                .await,
            Err(CertificateError::Protocol(_))
        ));
    }
}
