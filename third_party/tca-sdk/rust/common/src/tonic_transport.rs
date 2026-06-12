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

use crate::error::CertificateError;
use crate::transport::TcaTransport;
use async_trait::async_trait;
use trusted_certificate_authority_proto::google::tca::v1::trusted_certificate_authority_client::TrustedCertificateAuthorityClient;
use trusted_certificate_authority_proto::google::tca::v1::{
    IssueCertificateRequest, IssueCertificateResponse,
};

#[derive(Debug, Clone)]
pub struct TonicTcaTransport {
    endpoint: String,
}

impl TonicTcaTransport {
    pub fn new(endpoint: impl Into<String>) -> Self {
        Self { endpoint: endpoint.into() }
    }
}

#[async_trait]
impl TcaTransport for TonicTcaTransport {
    async fn issue_certificate(
        &self,
        request: IssueCertificateRequest,
    ) -> Result<IssueCertificateResponse, CertificateError> {
        let mut client = TrustedCertificateAuthorityClient::connect(self.endpoint.clone())
            .await
            .map_err(|e| CertificateError::Network(format!("Failed to connect to TCA: {}", e)))?;

        client
            .issue_certificate(request)
            .await
            .map_err(|e| CertificateError::Network(format!("TCA issuance failed: {}", e)))
            .map(|r| r.into_inner())
    }
}
