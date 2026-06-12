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

use crate::attestation::OakAttestationProvider;
use async_trait::async_trait;
use tca_common::adapters::TonicTcaTransport;
use tca_common::requirements::{AttestationProvider, TcaTransport};
use tca_common::StandardTcaClient;
use tca_common::{CertificateChain, CertificateError, Csr, TcaClient};

#[derive(Debug, Clone)]
pub struct OakTcaClient<P, T> {
    inner: StandardTcaClient<P, T>,
}

impl OakTcaClient<OakAttestationProvider, TonicTcaTransport> {
    pub async fn create(endpoint: impl Into<String>) -> Result<Self, CertificateError> {
        Ok(Self {
            inner: StandardTcaClient::new(
                OakAttestationProvider::create_default().await?,
                TonicTcaTransport::new(endpoint.into()),
            ),
        })
    }
}

impl<P: AttestationProvider, T: TcaTransport> OakTcaClient<P, T> {
    pub fn with_transport(provider: P, transport: T) -> Self {
        Self { inner: StandardTcaClient::new(provider, transport) }
    }
}

#[async_trait]
impl<P: AttestationProvider + Send + Sync, T: TcaTransport + Send + Sync> TcaClient
    for OakTcaClient<P, T>
{
    async fn issue_certificate(&self, csr: Csr) -> Result<CertificateChain, CertificateError> {
        self.inner.issue_certificate(csr).await
    }
}
