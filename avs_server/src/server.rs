//
// Copyright 2025 Google LLC
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

use crate::{ca, csr};
use avs_proto_rust::avs::{
    attestation_verification_server::AttestationVerification, certify_attestation_stream_request,
    certify_attestation_stream_response, CertifyAttestationRequest, CertifyAttestationResponse,
    CertifyAttestationStreamRequest, CertifyAttestationStreamResponse, ChallengeResponse,
    GenerateAvsSigningKeyRequest, GenerateAvsSigningKeyResponse,
};
use std::pin::Pin;
use std::sync::Arc;
use tokio::sync::RwLock;
use tokio_stream::{wrappers::ReceiverStream, Stream, StreamExt};
use tonic::{Request, Response, Status};

pub struct AttestationVerificationService {
    tca_client: Option<Arc<dyn tca_common::TcaClient>>,
    certificate_authority: RwLock<Option<Arc<ca::CertificateAuthority>>>,
}

impl AttestationVerificationService {
    pub fn new(tca_client: Option<Arc<dyn tca_common::TcaClient>>) -> Self {
        Self { tca_client, certificate_authority: RwLock::new(None) }
    }

    /// Returns the DER-encoded CA certificate chain, if the certificate
    /// authority has been initialized.
    pub async fn get_ca_certificate_chain(&self) -> Option<Vec<Vec<u8>>> {
        let ca = self.certificate_authority.read().await;
        ca.as_ref().map(|ca| ca.get_ca_cert_chain_der().to_vec())
    }
}

#[tonic::async_trait]
impl AttestationVerification for AttestationVerificationService {
    async fn certify_attestation(
        &self,
        request: Request<CertifyAttestationRequest>,
    ) -> Result<Response<CertifyAttestationResponse>, Status> {
        let certificate_authority = self.certificate_authority.read().await;
        let certificate_authority = certificate_authority.as_ref().ok_or_else(|| {
            Status::failed_precondition(
                "certificate authority has not been initialized; call GenerateAvsSigningKey first",
            )
        })?;

        let req = request.into_inner();

        let Some(ref evidence) = req.evidence else {
            return Err(Status::failed_precondition("request is missing `evidence`"));
        };

        let Some(ref endorsements) = req.endorsements else {
            return Err(Status::failed_precondition("request is missing `endorsements`"));
        };

        let Some(ref operator_info) = req.operator_info else {
            return Err(Status::failed_precondition("request is missing `operator_info`"));
        };

        let identity = csr::validate_csr_request(
            req.csr.as_slice(),
            evidence,
            endorsements,
            None,
            req.policy_hint,
            operator_info,
        )
        .map_err(|e| Status::new(tonic::Code::FailedPrecondition, format!("{e:?}")))?;
        let cert = certificate_authority.generate_certificate(&identity).map_err(|e| {
            Status::new(tonic::Code::Internal, format!("Failed to generate certificate: {e:?}"))
        })?;
        let mut certificate_chain = vec![cert];
        certificate_chain.extend_from_slice(certificate_authority.get_ca_cert_chain_der());
        let reply = CertifyAttestationResponse { certificate_chain };

        Ok(Response::new(reply))
    }

    type CertifyAttestationStreamStream =
        Pin<Box<dyn Stream<Item = Result<CertifyAttestationStreamResponse, Status>> + Send>>;

    async fn certify_attestation_stream(
        &self,
        request: Request<tonic::Streaming<CertifyAttestationStreamRequest>>,
    ) -> Result<Response<Self::CertifyAttestationStreamStream>, Status> {
        let certificate_authority = self.certificate_authority.read().await;
        let certificate_authority = certificate_authority
            .as_ref()
            .ok_or_else(|| {
                Status::failed_precondition(
                "certificate authority has not been initialized; call GenerateAvsSigningKey first",
            )
            })?
            .clone();

        let mut stream = request.into_inner();
        let (tx, rx) = tokio::sync::mpsc::channel(1);

        tokio::spawn(async move {
            // 1. Wait for ChallengeRequest
            let msg = match stream.next().await {
                Some(Ok(msg)) => msg,
                Some(Err(e)) => {
                    let _ = tx.send(Err(Status::internal(format!("Stream error: {e:?}")))).await;
                    return;
                }
                None => {
                    let _ =
                        tx.send(Err(Status::invalid_argument("Expected challenge_request"))).await;
                    return;
                }
            };

            if !matches!(
                msg.request,
                Some(certify_attestation_stream_request::Request::ChallengeRequest(_))
            ) {
                let _ = tx.send(Err(Status::invalid_argument("Expected challenge_request"))).await;
                return;
            }

            // 2. Generate and send nonce
            let mut nonce = vec![0u8; 32];
            unsafe {
                bssl_sys::RAND_bytes(nonce.as_mut_ptr(), nonce.len());
            }

            let challenge_response = CertifyAttestationStreamResponse {
                response: Some(certify_attestation_stream_response::Response::ChallengeResponse(
                    ChallengeResponse { nonce: nonce.clone() },
                )),
            };
            if tx.send(Ok(challenge_response)).await.is_err() {
                return;
            }

            // 3. Wait for CertifyAttestationRequest (finish)
            let msg = match stream.next().await {
                Some(Ok(msg)) => msg,
                Some(Err(e)) => {
                    let _ = tx.send(Err(Status::internal(format!("Stream error: {e:?}")))).await;
                    return;
                }
                None => {
                    let _ = tx.send(Err(Status::invalid_argument("Expected finish request"))).await;
                    return;
                }
            };

            let certify_request = match msg.request {
                Some(certify_attestation_stream_request::Request::CertifyRequest(r)) => r,
                _ => {
                    let _ = tx.send(Err(Status::invalid_argument("Expected finish request"))).await;
                    return;
                }
            };

            // 4. Validate and send certificate
            let evidence = match certify_request.evidence {
                Some(e) => e,
                None => {
                    let _ = tx.send(Err(Status::failed_precondition("missing evidence"))).await;
                    return;
                }
            };
            let endorsements = match certify_request.endorsements {
                Some(e) => e,
                None => {
                    let _ = tx.send(Err(Status::failed_precondition("missing endorsements"))).await;
                    return;
                }
            };
            let operator_info = match certify_request.operator_info {
                Some(o) => o,
                None => {
                    let _ =
                        tx.send(Err(Status::failed_precondition("missing operator_info"))).await;
                    return;
                }
            };

            match csr::validate_csr_request(
                certify_request.csr.as_slice(),
                &evidence,
                &endorsements,
                Some(&nonce),
                certify_request.policy_hint,
                &operator_info,
            ) {
                Ok(identity) => match certificate_authority.generate_certificate(&identity) {
                    Ok(cert) => {
                        let mut certificate_chain = vec![cert];
                        certificate_chain
                            .extend_from_slice(certificate_authority.get_ca_cert_chain_der());
                        let reply = CertifyAttestationStreamResponse {
                            response: Some(
                                certify_attestation_stream_response::Response::CertifyResponse(
                                    CertifyAttestationResponse { certificate_chain },
                                ),
                            ),
                        };
                        let _ = tx.send(Ok(reply)).await;
                    }
                    Err(e) => {
                        let _ = tx
                            .send(Err(Status::internal(format!(
                                "Failed to generate certificate: {e:?}"
                            ))))
                            .await;
                    }
                },
                Err(e) => {
                    let _ = tx
                        .send(Err(Status::failed_precondition(format!("Validation failed: {e:?}"))))
                        .await;
                }
            }
        });

        Ok(Response::new(Box::pin(ReceiverStream::new(rx))))
    }

    async fn generate_avs_signing_key(
        &self,
        _request: Request<GenerateAvsSigningKeyRequest>,
    ) -> Result<Response<GenerateAvsSigningKeyResponse>, Status> {
        let new_ca = match &self.tca_client {
            // Intermediate certificate (signed by TCA)
            Some(tca_client) => ca::CertificateAuthority::new_intermediate(tca_client.clone())
                .await
                .map_err(map_tca_error)?,
            // Self-signed certificate
            None => ca::CertificateAuthority::new_root().map_err(|e| {
                Status::internal(format!("Failed to create root certificate authority: {e:?}"))
            })?,
        };

        let new_certificate_chain = new_ca.get_ca_cert_chain_der().to_vec();
        let new_ca = Arc::new(new_ca);

        let mut ca_lock = self.certificate_authority.write().await;
        *ca_lock = Some(new_ca);

        Ok(Response::new(GenerateAvsSigningKeyResponse { new_certificate_chain }))
    }
}

fn map_tca_error(e: anyhow::Error) -> Status {
    if let Some(cert_err) = e.downcast_ref::<tca_common::CertificateError>() {
        match cert_err {
            tca_common::CertificateError::Network(msg) => Status::unavailable(msg.clone()),
            _ => Status::internal(format!("TCA Error: {:?}", cert_err)),
        }
    } else {
        Status::internal(format!("Failed to create intermediate certificate authority: {e:?}"))
    }
}
