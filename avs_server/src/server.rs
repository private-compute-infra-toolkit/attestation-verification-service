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

use crate::{ca, csr, operator_info::OperatorInfo};
use avs_proto_rust::avs::{
    attestation_verification_server::AttestationVerification, certify_attestation_request,
    certify_attestation_stream_request, certify_attestation_stream_response, CertificateProfile,
    CertifyAttestationRequest, CertifyAttestationResponse, CertifyAttestationStreamRequest,
    CertifyAttestationStreamResponse, ChallengeResponse, GenerateAvsSigningKeyRequest,
    GenerateAvsSigningKeyResponse, PolicyHint,
};
use std::pin::Pin;
use std::sync::Arc;
use tokio::sync::RwLock;
use tokio_stream::{wrappers::ReceiverStream, Stream, StreamExt};
use tonic::{Request, Response, Status};

/// Maps a legacy `PolicyHint` to its corresponding policy name and certificate
/// profile.
fn resolve_legacy_hint(hint: PolicyHint) -> anyhow::Result<(&'static str, CertificateProfile)> {
    match hint {
        PolicyHint::Unspecified => {
            anyhow::bail!("cannot resolve policy name for POLICY_HINT_UNSPECIFIED")
        }
        PolicyHint::PrivateArateaFrontendCbCertificate => {
            Ok(("private_aratea_server", CertificateProfile::Unrestricted))
        }
        PolicyHint::EzEnforcerCbCertificate => Ok(("encrypted_zone", CertificateProfile::Mtls)),
        PolicyHint::EzTsmCbFrontendCertificate => Ok(("encrypted_zone", CertificateProfile::Tls)),
        PolicyHint::ProberCbCertificate => Ok(("prober", CertificateProfile::Unrestricted)),
        PolicyHint::DevelopmentCbCertificate => {
            Ok(("development", CertificateProfile::Unrestricted))
        }
        PolicyHint::DevelopmentMtlsCbCertificate => Ok(("development", CertificateProfile::Mtls)),
        PolicyHint::DevelopmentTlsCbCertificate => Ok(("development", CertificateProfile::Tls)),
    }
}

/// Resolves the policy selector of a `CertifyAttestationRequest` into a
/// concrete policy name and certificate profile.
///
/// A request carries exactly one selector variant: either the preferred
/// `CertificationParameters` (explicit policy name + certificate profile) or
/// the deprecated `PolicyHint`. The two are mutually exclusive by construction
/// (they share a `oneof`), so no cross-field validation is needed.
#[allow(deprecated)]
fn resolve_policy_request(
    selector: Option<certify_attestation_request::Selector>,
) -> Result<(String, CertificateProfile), Status> {
    match selector {
        None => Err(Status::invalid_argument(
            "a policy selector is required: set `certification_parameters` (or the deprecated \
             `policy_hint`)",
        )),
        Some(certify_attestation_request::Selector::CertificationParameters(params)) => {
            if params.policy_name.is_empty() {
                return Err(Status::invalid_argument("`policy_name` must not be empty"));
            }
            let profile = CertificateProfile::try_from(params.certificate_profile)
                .unwrap_or(CertificateProfile::Unspecified);
            if profile == CertificateProfile::Unspecified {
                return Err(Status::invalid_argument(
                    "`certificate_profile` is required when `policy_name` is specified",
                ));
            }
            Ok((params.policy_name, profile))
        }
        Some(certify_attestation_request::Selector::PolicyHint(hint)) => {
            let hint = PolicyHint::try_from(hint).unwrap_or(PolicyHint::Unspecified);
            let (name, profile) = resolve_legacy_hint(hint)
                .map_err(|e| Status::invalid_argument(format!("{e:?}")))?;
            Ok((name.to_string(), profile))
        }
    }
}

pub struct AttestationVerificationService {
    tca_client: Option<Arc<dyn tca_common::TcaClient>>,
    certificate_authority: RwLock<Option<Arc<ca::CertificateAuthority>>>,
    policies_config: policies::PoliciesConfig,
}

impl AttestationVerificationService {
    pub fn new(tca_client: Option<Arc<dyn tca_common::TcaClient>>) -> Self {
        Self {
            tca_client,
            certificate_authority: RwLock::new(None),
            policies_config: policies::PoliciesConfig::default(),
        }
    }

    pub fn new_with_policies_config(
        tca_client: Option<Arc<dyn tca_common::TcaClient>>,
        policies_config: policies::PoliciesConfig,
    ) -> Self {
        Self { tca_client, certificate_authority: RwLock::new(None), policies_config }
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

        let Some(ref operator_info_proto) = req.operator_info else {
            return Err(Status::invalid_argument("request is missing `operator_info`"));
        };

        let operator_info = OperatorInfo::try_from(operator_info_proto)?;

        let (policy_name, certificate_profile) = resolve_policy_request(req.selector)?;

        let identity = csr::validate_csr_request(
            req.csr.as_slice(),
            evidence,
            endorsements,
            None,
            &policy_name,
            certificate_profile,
            &operator_info,
            &self.policies_config,
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
        let policies_config = self.policies_config.clone();
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
                    let _ = tx.send(Err(Status::invalid_argument("missing evidence"))).await;
                    return;
                }
            };
            let endorsements = match certify_request.endorsements {
                Some(e) => e,
                None => {
                    let _ = tx.send(Err(Status::invalid_argument("missing endorsements"))).await;
                    return;
                }
            };
            let operator_info_proto = match certify_request.operator_info {
                Some(o) => o,
                None => {
                    let _ = tx.send(Err(Status::invalid_argument("missing operator_info"))).await;
                    return;
                }
            };

            let operator_info = match OperatorInfo::try_from(operator_info_proto) {
                Ok(o) => o,
                Err(e) => {
                    let _ = tx.send(Err(e.into())).await;
                    return;
                }
            };

            let (policy_name, certificate_profile) =
                match resolve_policy_request(certify_request.selector) {
                    Ok(res) => res,
                    Err(e) => {
                        let _ = tx.send(Err(e)).await;
                        return;
                    }
                };

            match csr::validate_csr_request(
                certify_request.csr.as_slice(),
                &evidence,
                &endorsements,
                Some(&nonce),
                &policy_name,
                certificate_profile,
                &operator_info,
                &policies_config,
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_resolve_legacy_hint() {
        assert_eq!(
            resolve_legacy_hint(PolicyHint::PrivateArateaFrontendCbCertificate).unwrap(),
            ("private_aratea_server", CertificateProfile::Unrestricted)
        );
        assert_eq!(
            resolve_legacy_hint(PolicyHint::EzEnforcerCbCertificate).unwrap(),
            ("encrypted_zone", CertificateProfile::Mtls)
        );
        assert_eq!(
            resolve_legacy_hint(PolicyHint::EzTsmCbFrontendCertificate).unwrap(),
            ("encrypted_zone", CertificateProfile::Tls)
        );
        assert_eq!(
            resolve_legacy_hint(PolicyHint::ProberCbCertificate).unwrap(),
            ("prober", CertificateProfile::Unrestricted)
        );
        assert_eq!(
            resolve_legacy_hint(PolicyHint::DevelopmentCbCertificate).unwrap(),
            ("development", CertificateProfile::Unrestricted)
        );
        assert_eq!(
            resolve_legacy_hint(PolicyHint::DevelopmentMtlsCbCertificate).unwrap(),
            ("development", CertificateProfile::Mtls)
        );
        assert_eq!(
            resolve_legacy_hint(PolicyHint::DevelopmentTlsCbCertificate).unwrap(),
            ("development", CertificateProfile::Tls)
        );
        assert!(resolve_legacy_hint(PolicyHint::Unspecified).is_err());
    }
}
