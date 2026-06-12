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

mod attestation;
mod client;

pub use client::OakTcaClient;
pub use tca_common::{Certificate, CertificateChain, CertificateError, Csr, TcaClient};

#[cfg(test)]
mod tests {
    use crate::attestation::OakAttestationProvider;
    use oak_proto_rust::oak::crypto::v1::Signature;
    use oak_proto_rust::oak::session::v1::EndorsedEvidence;
    use trusted_certificate_authority_proto::google::tca::v1::attestation_evidence::Evidence;

    #[test]
    fn test_convert_to_proto() {
        let evidence = EndorsedEvidence {
            evidence: Some(oak_proto_rust::oak::attestation::v1::Evidence::default()),
            endorsements: Some(oak_proto_rust::oak::attestation::v1::Endorsements::default()),
        };
        let signature = Signature { signature: vec![1, 2, 3] };

        let result = OakAttestationProvider::convert_to_proto(evidence, signature);
        assert!(result.is_ok());
        let attestation_evidence = result.unwrap();
        assert!(attestation_evidence.evidence.is_some());

        if let Some(Evidence::OakAttestationEvidence(oak_evidence)) = attestation_evidence.evidence
        {
            assert_eq!(oak_evidence.signed_public_key, vec![1, 2, 3]);
        } else {
            panic!("Expected OakAttestationEvidence");
        }
    }
}
