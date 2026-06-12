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

mod api;
mod attestation;
mod client;
pub mod error;
mod tonic_transport;
mod transport;
pub mod types;

pub use api::TcaClient;
pub use client::StandardTcaClient;
pub use error::CertificateError;
pub use types::{Certificate, CertificateChain, Csr};

pub mod requirements {
    pub use crate::attestation::AttestationProvider;
    pub use crate::transport::TcaTransport;
}

pub mod adapters {
    pub use crate::tonic_transport::TonicTcaTransport;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_certificate_error_display() {
        let err = CertificateError::Platform("test error".to_string());
        assert_eq!(format!("{}", err), "Platform error: test error");
    }

    #[test]
    fn test_types_wrappers() {
        let cert = Certificate(vec![1, 2, 3]);
        assert_eq!(cert.0, vec![1, 2, 3]);

        let chain = CertificateChain(vec![cert.clone()]);
        assert_eq!(chain.0.len(), 1);
        assert_eq!(chain.0[0], cert);

        let csr = Csr(vec![4, 5, 6]);
        assert_eq!(csr.0, vec![4, 5, 6]);
    }
    #[test]
    fn test_csr_public_key_extraction() {
        use rsa::pkcs1v15::{Signature, SigningKey};
        use rsa::sha2::Sha256;
        use rsa::RsaPrivateKey;
        use std::str::FromStr;
        use x509_cert::builder::{Builder, RequestBuilder};
        use x509_cert::der::Encode;
        use x509_cert::name::Name;

        let mut rng = rand::rngs::OsRng;
        let private_key = RsaPrivateKey::new(&mut rng, 2048).unwrap();
        let subject = Name::from_str("CN=Test").unwrap();
        let signing_key = SigningKey::<Sha256>::new(private_key);
        let builder = RequestBuilder::new(subject, &signing_key).unwrap();
        let csr = builder.build::<Signature>().unwrap();
        let csr_der = csr.to_der().unwrap();

        let csr_wrapper = Csr(csr_der);
        let public_key = csr_wrapper.public_key();
        assert!(public_key.is_ok());
        assert!(!public_key.unwrap().is_empty());
    }
}
