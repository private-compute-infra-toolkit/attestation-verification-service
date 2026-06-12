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

/// A wrapper around a DER-encoded X.509 certificate.
#[derive(Debug, Clone, PartialEq)]
pub struct Certificate(pub Vec<u8>);

impl From<Vec<u8>> for Certificate {
    fn from(bytes: Vec<u8>) -> Self {
        Self(bytes)
    }
}

/// A wrapper around a chain of X.509 certificates.
#[derive(Debug, Clone, PartialEq)]
pub struct CertificateChain(pub Vec<Certificate>);

impl From<Vec<Certificate>> for CertificateChain {
    fn from(certs: Vec<Certificate>) -> Self {
        Self(certs)
    }
}

use crate::error::CertificateError;
use x509_cert::der::{Decode, Encode};
use x509_cert::request::CertReq;

/// A wrapper around a DER-encoded Certificate Signing Request (CSR).
#[derive(Debug, Clone, PartialEq)]
pub struct Csr(pub Vec<u8>);

impl From<Vec<u8>> for Csr {
    fn from(bytes: Vec<u8>) -> Self {
        Self(bytes)
    }
}

impl Csr {
    /// Extracts the SubjectPublicKeyInfo bytes from the CSR.
    pub fn public_key(&self) -> Result<Vec<u8>, CertificateError> {
        let req = CertReq::from_der(&self.0)
            .map_err(|e| CertificateError::Protocol(format!("Failed to parse CSR: {}", e)))?;
        req.info
            .public_key
            .to_der()
            .map_err(|e| CertificateError::Protocol(format!("Failed to encode SPKI: {}", e)))
    }
}
