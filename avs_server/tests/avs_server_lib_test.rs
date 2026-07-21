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

#![allow(unused_imports, dead_code, unused_variables)]

use std::{
    net::{IpAddr, Ipv4Addr, SocketAddr},
    sync::Arc,
};

use avs_proto_rust::avs::{
    attestation_verification_client::AttestationVerificationClient,
    attestation_verification_server::AttestationVerificationServer,
    certify_attestation_stream_request, certify_attestation_stream_response,
    CertifyAttestationRequest, CertifyAttestationResponse, CertifyAttestationStreamRequest,
    ChallengeRequest, GenerateAvsSigningKeyRequest, OperatorInfo, PolicyHint,
};
use avs_server_lib::policies;
use avs_server_lib::server::AttestationVerificationService;
use chrono::{Duration, Utc};
use coset::{iana, CborSerializable, CoseSign1Builder, HeaderBuilder};
use oak_proto_rust::oak::attestation::v1::{
    endorsements, AmdSevSnpEndorsement, Endorsements, Evidence, OakContainersEndorsements,
};
use oak_proto_rust::oak::Variant;
use p256::ecdsa::{signature::Signer, SigningKey};
use prost::Message;
use tokio::{net::TcpListener, sync::Notify, task::JoinHandle};
use tokio_stream::StreamExt;
use tonic::transport::Server;
use x509_cert::der::{Decode, Encode};

fn get_evidence() -> Evidence {
    Evidence::decode(include_bytes!("../testdata/redacted_evidence.binarypb").as_slice()).unwrap()
}

fn get_milan_vcek() -> Vec<u8> {
    include_bytes!("../testdata/vcek_milan.crt").to_vec()
}

fn get_genoa_vcek() -> Vec<u8> {
    include_bytes!("../testdata/vcek_genoa.crt").to_vec()
}

fn create_signed_user_data_certificate(payload: &[u8], private_key_hex: &str) -> Vec<u8> {
    let key_bytes = hex::decode(private_key_hex).expect("invalid hex");
    let signing_key = SigningKey::from_bytes(key_bytes.as_slice().into()).expect("invalid key");

    let protected = HeaderBuilder::new().algorithm(iana::Algorithm::ES256).build();

    let unprotected = HeaderBuilder::new().key_id(b"AsymmetricECDSA256".to_vec()).build();

    let cose_sign1 = CoseSign1Builder::new()
        .protected(protected)
        .unprotected(unprotected)
        .payload(payload.to_vec())
        .create_signature(&[], |data| {
            let signature: p256::ecdsa::Signature = signing_key.sign(data);
            signature.to_bytes().to_vec()
        })
        .build();

    cose_sign1.to_vec().expect("failed to encode COSE_Sign1")
}

#[derive(Clone, Debug)]
enum ServerMode {
    SelfSigning,
    TcaMock,
}

struct TestServer {
    server: JoinHandle<()>,
    port: u16,
    shutdown_notify: Arc<Notify>,
}

async fn create_test_server(mode: ServerMode) -> anyhow::Result<TestServer> {
    create_test_server_with_config(mode, policies::PoliciesConfig::default()).await
}

async fn create_test_server_with_config(
    mode: ServerMode,
    policies_config: policies::PoliciesConfig,
) -> anyhow::Result<TestServer> {
    let sockaddr = SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0);
    let listener = TcpListener::bind(sockaddr).await?;
    let port = listener.local_addr()?.port();
    let shutdown_notify = Arc::new(Notify::new());
    let shutdown_notify_copy = shutdown_notify.clone();

    let attestation_verification_service = match mode {
        ServerMode::SelfSigning => {
            AttestationVerificationService::new_with_policies_config(None, policies_config)
        }
        ServerMode::TcaMock => {
            let mock_client = MockTcaClient::new();
            let tca_client: Arc<dyn tca_common::TcaClient> = std::sync::Arc::new(mock_client);
            AttestationVerificationService::new_with_policies_config(
                Some(tca_client),
                policies_config,
            )
        }
    };
    let server = tokio::spawn(async move {
        let _ = Server::builder()
            .add_service(AttestationVerificationServer::new(attestation_verification_service))
            .serve_with_incoming_shutdown(
                tokio_stream::wrappers::TcpListenerStream::new(listener),
                shutdown_notify_copy.notified(),
            )
            .await;
    });

    // Initialize the certificate authority via gRPC.
    let mut client =
        AttestationVerificationClient::connect(format!("http://localhost:{}", port)).await?;
    client.generate_avs_signing_key(GenerateAvsSigningKeyRequest {}).await?;

    Ok(TestServer { server, port, shutdown_notify })
}

async fn call_certify_attestation(
    port: u16,
    request: CertifyAttestationRequest,
) -> anyhow::Result<CertifyAttestationResponse> {
    let mut client =
        AttestationVerificationClient::connect(format!("http://localhost:{}", port)).await?;
    let response = client.certify_attestation(request).await?;
    Ok(response.into_inner())
}

fn generate_csr(subject: &str) -> anyhow::Result<(Vec<u8>, rcgen::KeyPair)> {
    let key_pair = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256)?;
    let csr = generate_csr_with_key(subject, &key_pair)?;
    Ok((csr, key_pair))
}

fn generate_csr_with_key(subject: &str, key_pair: &rcgen::KeyPair) -> anyhow::Result<Vec<u8>> {
    let mut params = rcgen::CertificateParams::new(vec![])?;
    params.distinguished_name.push(rcgen::DnType::CommonName, subject);
    let csr = params.serialize_request(&key_pair)?;
    Ok(csr.der().to_vec())
}

fn extract_san_uri(der: &[u8]) -> anyhow::Result<Vec<String>> {
    let san = x509_cert::ext::pkix::SubjectAltName::from_der(der)?;
    let mut result = vec![];
    for name in san.0.iter() {
        if let x509_cert::ext::pkix::name::GeneralName::UniformResourceIdentifier(uri) = name {
            result.push(uri.as_str().to_string());
        }
    }
    Ok(result)
}

fn extract_san_dns(der: &[u8]) -> anyhow::Result<Vec<String>> {
    let san = x509_cert::ext::pkix::SubjectAltName::from_der(der)?;
    let mut result = vec![];
    for name in san.0.iter() {
        if let x509_cert::ext::pkix::name::GeneralName::DnsName(dns) = name {
            result.push(dns.as_str().to_string());
        }
    }
    Ok(result)
}

fn get_spiffe_id(extensions: &Option<Vec<x509_cert::ext::Extension>>) -> anyhow::Result<String> {
    const SAN_OID: x509_cert::spki::ObjectIdentifier =
        x509_cert::spki::ObjectIdentifier::new_unwrap("2.5.29.17");
    if let Some(extensions) = extensions {
        for ext in extensions.iter() {
            if ext.extn_id == SAN_OID {
                let uris = extract_san_uri(ext.extn_value.as_bytes())?;
                if uris.len() != 1 {
                    anyhow::bail!("There are multiple URI fields in subject alt name extension");
                }
                return Ok(uris[0].clone());
            }
        }
    }
    anyhow::bail!("SPIFFE ID not found in certificate extensions")
}

fn get_dns_name(extensions: &Option<Vec<x509_cert::ext::Extension>>) -> anyhow::Result<String> {
    const SAN_OID: x509_cert::spki::ObjectIdentifier =
        x509_cert::spki::ObjectIdentifier::new_unwrap("2.5.29.17");
    if let Some(extensions) = extensions {
        for ext in extensions.iter() {
            if ext.extn_id == SAN_OID {
                let dns_names = extract_san_dns(ext.extn_value.as_bytes())?;
                if dns_names.len() != 1 {
                    anyhow::bail!("Expected exactly 1 DNS name in SAN, found {}", dns_names.len());
                }
                // Also verify no URI SANs are present.
                let uris = extract_san_uri(ext.extn_value.as_bytes())?;
                if !uris.is_empty() {
                    anyhow::bail!("Expected no URI SANs when DNS SAN is present, found {:?}", uris);
                }
                return Ok(dns_names[0].clone());
            }
        }
    }
    anyhow::bail!("DNS name not found in certificate extensions")
}

enum ExpectedSan {
    SpiffeUri(String),
    DnsName(String),
}

fn test_operator_info() -> OperatorInfo {
    OperatorInfo {
        operator_domain: "google".to_string(),
        operator_role: "encrypted-zone".to_string(),
    }
}

fn test_prober_operator_info() -> OperatorInfo {
    OperatorInfo { operator_domain: "google".to_string(), operator_role: "prober".to_string() }
}

enum ExpectedEku {
    None,
    ServerAuth,
    #[allow(dead_code)]
    ServerAndClientAuth,
}

/// Validates that a DNS name conforms to RFC 1123 rules.
fn assert_valid_dns_name(dns_name: &str) {
    assert!(!dns_name.is_empty(), "DNS name must not be empty");
    assert!(
        dns_name.len() <= 253,
        "DNS name exceeds 253 characters: {} (len={})",
        dns_name,
        dns_name.len()
    );

    let labels: Vec<&str> = dns_name.split('.').collect();
    assert!(
        labels.len() >= 2,
        "DNS name must have at least 2 labels (got {}): {}",
        labels.len(),
        dns_name
    );

    for (i, label) in labels.iter().enumerate() {
        assert!(!label.is_empty(), "DNS label at position {} is empty in: {}", i, dns_name);
        assert!(
            label.len() <= 63,
            "DNS label '{}' at position {} exceeds 63 characters (len={})",
            label,
            i,
            label.len()
        );
        assert!(
            label.chars().all(|c| c.is_ascii_alphanumeric() || c == '-'),
            "DNS label '{}' at position {} contains invalid characters (only alphanumeric and hyphens allowed)",
            label,
            i
        );
        assert!(
            !label.starts_with('-') && !label.ends_with('-'),
            "DNS label '{}' at position {} must not start or end with a hyphen",
            label,
            i
        );
    }
}

fn validate_cert_chain(
    certificate_chain: &[Vec<u8>],
    csr_key_pair: &rcgen::KeyPair,
    expected_san: &ExpectedSan,
    expected_eku: ExpectedEku,
    expected_issuer: &str,
) {
    assert!(!certificate_chain.is_empty(), "Certificate chain must not be empty");

    let leaf_cert = x509_cert::Certificate::from_der(&certificate_chain[0]).unwrap();
    let tbs = &leaf_cert.tbs_certificate;
    assert_eq!(tbs.issuer.to_string(), expected_issuer);

    // Check that the public key in the cert matches the CSR's public key
    // Note that there is a difference in how the two PEMs are formatted. One
    // leverages RFC 7468 (`\r\n`) and the other RFC 1421 (`\n`). To assert the two
    // PEMs are equal, we strip the `\r` characters from the RFC 7468 cert's PEM.
    let cert_pub_key_der = tbs.subject_public_key_info.to_der().unwrap();
    let cert_pub_key_pem =
        pem::encode(&pem::Pem::new("PUBLIC KEY", cert_pub_key_der)).replace('\r', "");
    let csr_pub_key_pem = csr_key_pair.public_key_pem();

    assert_eq!(
        cert_pub_key_pem, csr_pub_key_pem,
        "Certificate public key does not match CSR public key"
    );

    // Check validity period
    let now = Utc::now();
    let not_before_sys = tbs.validity.not_before.to_system_time();
    let not_before: chrono::DateTime<Utc> = not_before_sys.into();
    let not_after_sys = tbs.validity.not_after.to_system_time();
    let not_after: chrono::DateTime<Utc> = not_after_sys.into();
    assert!(now >= not_before - Duration::seconds(60));
    let expected_not_after = now + Duration::days(365);
    let delta = expected_not_after - not_after;
    assert!(
        delta.num_seconds().abs() < 120,
        "not_after is not within the expected range: now={}, not_after={}, expected={}",
        now,
        not_after,
        expected_not_after
    );

    // Validate that the certificate SAN matches the expected type and value.
    match expected_san {
        ExpectedSan::SpiffeUri(expected_uri) => {
            assert_eq!(get_spiffe_id(&tbs.extensions).unwrap(), *expected_uri);
        }
        ExpectedSan::DnsName(expected_dns) => {
            let actual_dns = get_dns_name(&tbs.extensions).unwrap();
            assert_valid_dns_name(&actual_dns);
            assert_eq!(actual_dns, *expected_dns);
        }
    }

    // Validate Extended Key Usage based on the expected connection mode.
    const EKU_OID: x509_cert::spki::ObjectIdentifier =
        x509_cert::spki::ObjectIdentifier::new_unwrap("2.5.29.37");
    let eku_ext =
        tbs.extensions.as_ref().and_then(|exts| exts.iter().find(|ext| ext.extn_id == EKU_OID));

    match expected_eku {
        ExpectedEku::None => {
            assert!(eku_ext.is_none(), "certificate must not have Extended Key Usage extension");
        }
        ExpectedEku::ServerAuth => {
            const SERVER_AUTH_OID: x509_cert::spki::ObjectIdentifier =
                x509_cert::spki::ObjectIdentifier::new_unwrap("1.3.6.1.5.5.7.3.1");
            const CLIENT_AUTH_OID: x509_cert::spki::ObjectIdentifier =
                x509_cert::spki::ObjectIdentifier::new_unwrap("1.3.6.1.5.5.7.3.2");
            let eku_ext = eku_ext.expect("certificate must have Extended Key Usage extension");
            let eku =
                x509_cert::ext::pkix::ExtendedKeyUsage::from_der(eku_ext.extn_value.as_bytes())
                    .expect("failed to parse Extended Key Usage extension");
            assert!(
                eku.0.contains(&SERVER_AUTH_OID),
                "EKU must contain serverAuth (1.3.6.1.5.5.7.3.1)"
            );
            assert!(
                !eku.0.contains(&CLIENT_AUTH_OID),
                "EKU must NOT contain clientAuth for TLS-only mode"
            );
        }
        ExpectedEku::ServerAndClientAuth => {
            const SERVER_AUTH_OID: x509_cert::spki::ObjectIdentifier =
                x509_cert::spki::ObjectIdentifier::new_unwrap("1.3.6.1.5.5.7.3.1");
            const CLIENT_AUTH_OID: x509_cert::spki::ObjectIdentifier =
                x509_cert::spki::ObjectIdentifier::new_unwrap("1.3.6.1.5.5.7.3.2");
            let eku_ext = eku_ext.expect("certificate must have Extended Key Usage extension");
            let eku =
                x509_cert::ext::pkix::ExtendedKeyUsage::from_der(eku_ext.extn_value.as_bytes())
                    .expect("failed to parse Extended Key Usage extension");
            assert!(
                eku.0.contains(&SERVER_AUTH_OID),
                "EKU must contain serverAuth (1.3.6.1.5.5.7.3.1)"
            );
            assert!(
                eku.0.contains(&CLIENT_AUTH_OID),
                "EKU must contain clientAuth (1.3.6.1.5.5.7.3.2)"
            );
        }
    }

    // Validate BasicConstraints: must be present, critical, with CA:FALSE.
    const BASIC_CONSTRAINTS_OID: x509_cert::spki::ObjectIdentifier =
        x509_cert::spki::ObjectIdentifier::new_unwrap("2.5.29.19");
    let bc_ext = tbs
        .extensions
        .as_ref()
        .and_then(|exts| exts.iter().find(|ext| ext.extn_id == BASIC_CONSTRAINTS_OID))
        .expect("leaf certificate must have BasicConstraints extension");
    assert!(bc_ext.critical, "BasicConstraints extension must be critical");
    let bc = x509_cert::ext::pkix::BasicConstraints::from_der(bc_ext.extn_value.as_bytes())
        .expect("failed to parse BasicConstraints extension");
    assert!(!bc.ca, "leaf certificate BasicConstraints must have CA:FALSE");

    // Validate Key Usage: must be present, critical, with digitalSignature.
    const KEY_USAGE_OID: x509_cert::spki::ObjectIdentifier =
        x509_cert::spki::ObjectIdentifier::new_unwrap("2.5.29.15");
    let ku_ext = tbs
        .extensions
        .as_ref()
        .and_then(|exts| exts.iter().find(|ext| ext.extn_id == KEY_USAGE_OID))
        .expect("leaf certificate must have Key Usage extension");
    assert!(ku_ext.critical, "Key Usage extension must be critical");
    let ku = x509_cert::ext::pkix::KeyUsage::from_der(ku_ext.extn_value.as_bytes())
        .expect("failed to parse Key Usage extension");
    assert!(ku.digital_signature(), "Key Usage must include digitalSignature");
    assert!(!ku.key_encipherment(), "Key Usage must NOT include keyEncipherment");

    // Validate that each certificate in the chain is signed by the next.
    for i in 0..certificate_chain.len() - 1 {
        let cert = x509_cert::Certificate::from_der(&certificate_chain[i]).unwrap();
        let issuer_cert = x509_cert::Certificate::from_der(&certificate_chain[i + 1]).unwrap();
        let key = x509_verify::VerifyingKey::try_from(&issuer_cert).unwrap();
        assert!(
            key.verify(&cert).is_ok(),
            "Certificate at index {} is not signed by certificate at index {}",
            i,
            i + 1
        );
    }
}

// private signing key for: `../testdata/redacted_evidence.binarypb`.
const SIGNING_PRIVATE_KEY_HEX: &str =
    "bef11204413b7987d5a04a6758bda66446a84bfb8d7b4de41d86d957ac8c6c91";

#[tokio::test]
async fn test_valid_certify_attestation() {
    for mode in [ServerMode::SelfSigning, ServerMode::TcaMock] {
        let test_server = create_test_server_with_config(
            mode.clone(),
            policies::PoliciesConfig { include_development_policy: true },
        )
        .await
        .unwrap();

        let platform_endorsement = AmdSevSnpEndorsement { tee_certificate: get_milan_vcek() };
        let empty_variant: Variant = Variant::default();
        let endorsements = Endorsements {
            platform: Some(platform_endorsement.into()),
            initial: Some(empty_variant),
            ..Default::default()
        };

        static SUBJECT: &str = "example.com";
        let (csr_der, csr_key_pair) = generate_csr(SUBJECT).unwrap();
        let public_key_pem = pem::parse(csr_key_pair.public_key_pem()).unwrap();
        let public_key_der = public_key_pem.contents();

        for (policy_hint, expected_eku, is_tls) in [
            (PolicyHint::DevelopmentCbCertificate, ExpectedEku::None, false),
            (PolicyHint::DevelopmentMtlsCbCertificate, ExpectedEku::ServerAndClientAuth, false),
            (PolicyHint::DevelopmentTlsCbCertificate, ExpectedEku::ServerAuth, true),
        ] {
            let mut evidence = get_evidence();
            evidence.signed_user_data_certificate =
                create_signed_user_data_certificate(public_key_der, SIGNING_PRIVATE_KEY_HEX);

            let request = CertifyAttestationRequest {
                csr: csr_der.clone(),
                evidence: Some(evidence),
                endorsements: Some(endorsements.clone()),
                operator_info: Some(test_operator_info()),
                policy_hint: policy_hint.into(),
            };

            let response = call_certify_attestation(test_server.port, request).await.unwrap();
            let (expected_chain_len, expected_trust_domain) = match mode {
                ServerMode::SelfSigning => (2, "prod.google.com.avs.pcit.goog"),
                ServerMode::TcaMock => (3, MOCK_TCA_TRUST_DOMAIN),
            };
            assert_eq!(
                response.certificate_chain.len(),
                expected_chain_len,
                "Expected {} certificates in chain for {:?} mode",
                expected_chain_len,
                mode
            );
            let (expected_publisher, expected_role, expected_workload) =
                ("untrusted.com", "none", "unendorsed-development");

            let expected_san = if is_tls {
                ExpectedSan::DnsName(format!("encrypted-zone.google.{}", expected_trust_domain))
            } else {
                ExpectedSan::SpiffeUri(format!(
                    "spiffe://{}/operator/google/encrypted-zone/publisher/{}/{}/workload/{}",
                    expected_trust_domain, expected_publisher, expected_role, expected_workload
                ))
            };

            let expected_issuer = match mode {
                ServerMode::SelfSigning => self_signing_issuer_name(),
                ServerMode::TcaMock => mock_tca_issuer_name(),
            };
            validate_cert_chain(
                &response.certificate_chain,
                &csr_key_pair,
                &expected_san,
                expected_eku,
                &expected_issuer,
            );
        }
        test_server.shutdown_notify.notify_waiters();
        test_server.server.await.unwrap();
    }
}

#[tokio::test]
async fn test_invalid_vcek_error() {
    for mode in [ServerMode::SelfSigning, ServerMode::TcaMock] {
        let test_server = create_test_server_with_config(
            mode.clone(),
            policies::PoliciesConfig { include_development_policy: true },
        )
        .await
        .unwrap();

        let invalid_platform_endorsement =
            AmdSevSnpEndorsement { tee_certificate: get_genoa_vcek() };
        let empty_variant: Variant = Variant::default();
        let invalid_endorsements = Endorsements {
            platform: Some(invalid_platform_endorsement.into()),
            initial: Some(empty_variant),
            ..Default::default()
        };

        static SUBJECT: &str = "example.com";
        let (csr_der, _) = generate_csr(SUBJECT).unwrap();
        let request = CertifyAttestationRequest {
            csr: csr_der,
            evidence: Some(get_evidence()),
            endorsements: Some(invalid_endorsements),
            operator_info: Some(test_operator_info()),
            policy_hint: PolicyHint::DevelopmentCbCertificate.into(),
        };

        match call_certify_attestation(test_server.port, request).await {
            Ok(_) => panic!("certify_attestation() should fail."),
            Err(e) => assert!(e.to_string().contains("chip id differs")),
        }

        let empty_platform_endorsement = AmdSevSnpEndorsement { tee_certificate: vec![] };
        let empty_variant: Variant = Variant::default();
        let empty_endorsements = Endorsements {
            platform: Some(empty_platform_endorsement.into()),
            initial: Some(empty_variant),
            ..Default::default()
        };

        let (csr_der, _) = generate_csr(SUBJECT).unwrap();
        let request = CertifyAttestationRequest {
            csr: csr_der,
            evidence: Some(get_evidence()),
            endorsements: Some(empty_endorsements),
            operator_info: Some(test_operator_info()),
            policy_hint: PolicyHint::DevelopmentCbCertificate.into(),
        };

        match call_certify_attestation(test_server.port, request).await {
            Ok(_) => panic!("certify_attestation() should fail."),
            Err(e) => assert!(e.to_string().contains("couldn't parse VCEK certificate")),
        }

        test_server.shutdown_notify.notify_waiters();
        test_server.server.await.unwrap();
    }
}

#[tokio::test]
async fn test_no_evidence_error() {
    for mode in [ServerMode::SelfSigning, ServerMode::TcaMock] {
        let test_server = create_test_server(mode.clone()).await.unwrap();

        static SUBJECT: &str = "example.com";
        let (csr_der, _) = generate_csr(SUBJECT).unwrap();
        let request = CertifyAttestationRequest {
            csr: csr_der,
            evidence: None,
            endorsements: Some(Endorsements {
                r#type: Some(endorsements::Type::OakContainers(OakContainersEndorsements {
                    root_layer: None,
                    container_layer: None,
                    kernel_layer: None,
                    system_layer: None,
                })),
                events: vec![],
                initial: None,
                platform: None,
            }),
            ..Default::default()
        };

        match call_certify_attestation(test_server.port, request).await {
            Ok(_) => panic!("certify_attestation() should fail."),
            Err(e) => assert!(e.to_string().contains("request is missing `evidence`")),
        }

        test_server.shutdown_notify.notify_waiters();
        test_server.server.await.unwrap();
    }
}

#[tokio::test]
async fn test_no_endorsements_error() {
    for mode in [ServerMode::SelfSigning, ServerMode::TcaMock] {
        let test_server = create_test_server(mode.clone()).await.unwrap();

        static SUBJECT: &str = "example.com";
        let (csr_der, _) = generate_csr(SUBJECT).unwrap();
        let request = CertifyAttestationRequest {
            csr: csr_der,
            evidence: Some(Evidence::default()),
            endorsements: None,
            ..Default::default()
        };

        match call_certify_attestation(test_server.port, request).await {
            Ok(_) => panic!("certify_attestation() should fail."),
            Err(e) => assert!(e.to_string().contains("request is missing `endorsements`")),
        }

        test_server.shutdown_notify.notify_waiters();
        test_server.server.await.unwrap();
    }
}

#[tokio::test]
async fn test_invalid_csr_error() {
    for mode in [ServerMode::SelfSigning, ServerMode::TcaMock] {
        let test_server = create_test_server(mode.clone()).await.unwrap();

        let platform_endorsement = AmdSevSnpEndorsement { tee_certificate: get_milan_vcek() };
        let empty_variant: Variant = Variant::default();
        let endorsements = Endorsements {
            platform: Some(platform_endorsement.into()),
            initial: Some(empty_variant),
            ..Default::default()
        };

        let request = CertifyAttestationRequest {
            csr: b"invalid".to_vec(),
            evidence: Some(get_evidence()),
            endorsements: Some(endorsements.clone()),
            operator_info: Some(test_operator_info()),
            ..Default::default()
        };

        match call_certify_attestation(test_server.port, request).await {
            Ok(_) => panic!("certify_attestation() should fail."),
            Err(e) => {
                assert!(e.to_string().contains("failed to parse CSR"), "unexpected error: {}", e)
            }
        }

        static SUBJECT: &str = "example.com";
        let (csr_der, _) = generate_csr(SUBJECT).unwrap();
        let request = CertifyAttestationRequest {
            csr: csr_der[0..csr_der.len() - 3].to_vec(),
            evidence: Some(get_evidence()),
            endorsements: Some(endorsements.clone()),
            operator_info: Some(test_operator_info()),
            ..Default::default()
        };

        match call_certify_attestation(test_server.port, request).await {
            Ok(_) => panic!("certify_attestation() should fail."),
            Err(e) => {
                assert!(e.to_string().contains("failed to parse CSR"), "unexpected error: {}", e)
            }
        }

        test_server.shutdown_notify.notify_waiters();
        test_server.server.await.unwrap();
    }
}

#[tokio::test]
// Test valid evidence and CSR where public key bound to evidence does not
// match the on in the CSR.
async fn test_mismatch_publickey() {
    for mode in [ServerMode::SelfSigning, ServerMode::TcaMock] {
        let test_server = create_test_server_with_config(
            mode.clone(),
            policies::PoliciesConfig { include_development_policy: true },
        )
        .await
        .unwrap();

        let platform_endorsement = AmdSevSnpEndorsement { tee_certificate: get_milan_vcek() };
        let empty_variant: Variant = Variant::default();
        let endorsements = Endorsements {
            platform: Some(platform_endorsement.into()),
            initial: Some(empty_variant),
            ..Default::default()
        };

        static SUBJECT: &str = "example.com";
        // Generate a CSR with a DIFFERENT key.
        let (csr_der, _) = generate_csr(SUBJECT).unwrap();

        let (_, mismatch_key_pair) = generate_csr(SUBJECT).unwrap();
        let public_key_pem = pem::parse(mismatch_key_pair.public_key_pem()).unwrap();
        let public_key_der = public_key_pem.contents();
        let mut evidence = get_evidence();
        evidence.signed_user_data_certificate =
            create_signed_user_data_certificate(public_key_der, SIGNING_PRIVATE_KEY_HEX);

        let request = CertifyAttestationRequest {
            csr: csr_der,
            evidence: Some(evidence),
            endorsements: Some(endorsements),
            operator_info: Some(test_operator_info()),
            policy_hint: PolicyHint::DevelopmentCbCertificate.into(),
        };

        match call_certify_attestation(test_server.port, request).await {
            Ok(_) => panic!("certify_attestation() should fail."),
            Err(e) => assert!(e
                .to_string()
                .contains("quoted key does not match the key in the certificate signing request")),
        }
        test_server.shutdown_notify.notify_waiters();
        test_server.server.await.unwrap();
    }
}

use async_trait::async_trait;
use tca_common::types::{Certificate, CertificateChain};
use tca_common::{error::CertificateError, Csr, TcaClient};

use rcgen::{CertificateParams, Issuer, KeyPair};

const MOCK_TCA_TRUST_DOMAIN: &str = "test.tca.pcit.goog";
const MOCK_TCA_ORG_NAME: &str = "Mock Org";
const MOCK_TCA_CN_NAME: &str = "Attestation Verification Service";

fn mock_tca_issuer_name() -> String {
    format!("O={},CN={}", MOCK_TCA_ORG_NAME, MOCK_TCA_CN_NAME)
}

fn self_signing_issuer_name() -> String {
    format!("CN={}", MOCK_TCA_CN_NAME)
}

struct MockTcaPublicKey {
    key_der: Vec<u8>,
}

impl rcgen::PublicKeyData for MockTcaPublicKey {
    fn algorithm(&self) -> &'static rcgen::SignatureAlgorithm {
        &rcgen::PKCS_RSA_SHA256
    }
    fn der_bytes(&self) -> &[u8] {
        &self.key_der
    }
}

struct MockTcaClient {
    root_ca_cert_der: Vec<u8>,
    root_ca_key: std::sync::Arc<KeyPair>,
}

impl MockTcaClient {
    fn new() -> Self {
        let ca_key = KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).unwrap();
        let ca_cert_der = Self::ca_params().self_signed(&ca_key).unwrap().der().to_vec();
        Self { root_ca_cert_der: ca_cert_der, root_ca_key: std::sync::Arc::new(ca_key) }
    }

    fn ca_params() -> CertificateParams {
        let mut ca_params = CertificateParams::new(vec![]).unwrap();
        ca_params.distinguished_name.push(rcgen::DnType::CommonName, "Mock CA");
        ca_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        ca_params.key_usages =
            vec![rcgen::KeyUsagePurpose::KeyCertSign, rcgen::KeyUsagePurpose::CrlSign];
        ca_params
    }
}

#[async_trait]
impl TcaClient for MockTcaClient {
    async fn issue_certificate(&self, csr: Csr) -> Result<CertificateChain, CertificateError> {
        let req = x509_cert::request::CertReq::from_der(&csr.0)
            .map_err(|e| CertificateError::Platform(format!("Failed to parse CSR: {:?}", e)))?;

        let key_der = req.info.public_key.subject_public_key.as_bytes().unwrap().to_vec();

        let avs_pub_key = MockTcaPublicKey { key_der };

        let ca_issuer = Issuer::new(Self::ca_params(), &*self.root_ca_key);

        let mut avs_params = CertificateParams::new(vec![]).unwrap();
        avs_params.distinguished_name.push(rcgen::DnType::OrganizationName, MOCK_TCA_ORG_NAME);
        avs_params.distinguished_name.push(rcgen::DnType::CommonName, MOCK_TCA_CN_NAME);
        avs_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        avs_params.subject_alt_names = vec![rcgen::SanType::URI(
            format!("spiffe://{}", MOCK_TCA_TRUST_DOMAIN).try_into().unwrap(),
        )];

        let avs_cert = avs_params
            .signed_by(&avs_pub_key, &ca_issuer)
            .map_err(|e| CertificateError::Platform(e.to_string()))?;

        // AVS issued certificate followed by the mock self-signed TCA certificate.
        Ok(CertificateChain(vec![
            Certificate(avs_cert.der().to_vec()),
            Certificate(self.root_ca_cert_der.clone()),
        ]))
    }
}

struct MockFailingTcaClient;

#[async_trait]
impl TcaClient for MockFailingTcaClient {
    async fn issue_certificate(&self, _csr: Csr) -> Result<CertificateChain, CertificateError> {
        Err(CertificateError::Network("simulated network failure".to_string()))
    }
}

// Mock TCA client that issues certs with multiple SAN entries (DNS + SPIFFE).
struct MockTcaClientMultiSan {
    root_ca_cert_der: Vec<u8>,
    root_ca_key: std::sync::Arc<KeyPair>,
}

impl MockTcaClientMultiSan {
    fn new() -> Self {
        let ca_key = KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).unwrap();
        let ca_cert_der = MockTcaClient::ca_params().self_signed(&ca_key).unwrap().der().to_vec();
        Self { root_ca_cert_der: ca_cert_der, root_ca_key: std::sync::Arc::new(ca_key) }
    }
}

#[async_trait]
impl TcaClient for MockTcaClientMultiSan {
    async fn issue_certificate(&self, csr: Csr) -> Result<CertificateChain, CertificateError> {
        let req = x509_cert::request::CertReq::from_der(&csr.0)
            .map_err(|e| CertificateError::Platform(format!("Failed to parse CSR: {:?}", e)))?;

        let key_der = req.info.public_key.subject_public_key.as_bytes().unwrap().to_vec();
        let avs_pub_key = MockTcaPublicKey { key_der };
        let ca_issuer = Issuer::new(MockTcaClient::ca_params(), &*self.root_ca_key);

        let mut avs_params = CertificateParams::new(vec![]).unwrap();
        avs_params.distinguished_name.push(rcgen::DnType::OrganizationName, MOCK_TCA_ORG_NAME);
        avs_params
            .distinguished_name
            .push(rcgen::DnType::CommonName, "Attestation Verification Service");
        avs_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        avs_params.subject_alt_names = vec![
            rcgen::SanType::DnsName("avs.example.com".try_into().unwrap()),
            rcgen::SanType::URI(format!("spiffe://{}", MOCK_TCA_TRUST_DOMAIN).try_into().unwrap()),
            rcgen::SanType::DnsName("avs2.example.com".try_into().unwrap()),
        ];

        let avs_cert = avs_params
            .signed_by(&avs_pub_key, &ca_issuer)
            .map_err(|e| CertificateError::Platform(e.to_string()))?;

        Ok(CertificateChain(vec![
            Certificate(avs_cert.der().to_vec()),
            Certificate(self.root_ca_cert_der.clone()),
        ]))
    }
}

#[tokio::test]
async fn test_generate_avs_signing_key_with_failing_tca_client() {
    let tca_client: Arc<dyn TcaClient> = std::sync::Arc::new(MockFailingTcaClient);
    let service = AttestationVerificationService::new(Some(tca_client));

    let sockaddr = SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0);
    let listener = TcpListener::bind(sockaddr).await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let shutdown_notify = Arc::new(Notify::new());
    let shutdown_notify_copy = shutdown_notify.clone();

    let server = tokio::spawn(async move {
        let _ = Server::builder()
            .add_service(AttestationVerificationServer::new(service))
            .serve_with_incoming_shutdown(
                tokio_stream::wrappers::TcpListenerStream::new(listener),
                shutdown_notify_copy.notified(),
            )
            .await;
    });

    let mut client =
        AttestationVerificationClient::connect(format!("http://localhost:{}", port)).await.unwrap();
    let result = client.generate_avs_signing_key(GenerateAvsSigningKeyRequest {}).await;
    match result {
        Ok(_) => panic!("Expected error from generate_avs_signing_key"),
        Err(e) => {
            assert_eq!(e.code(), tonic::Code::Unavailable);
            assert!(e.message().contains("simulated network failure"));
        }
    }

    shutdown_notify.notify_waiters();
    server.await.unwrap();
}

#[tokio::test]
async fn test_extract_trust_domain_with_multiple_san_entries() {
    let mock_client = MockTcaClientMultiSan::new();
    let tca_client: Arc<dyn TcaClient> = std::sync::Arc::new(mock_client);
    let service = AttestationVerificationService::new_with_policies_config(
        Some(tca_client),
        policies::PoliciesConfig { include_development_policy: true },
    );

    let sockaddr = SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0);
    let listener = TcpListener::bind(sockaddr).await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let shutdown_notify = Arc::new(Notify::new());
    let shutdown_notify_copy = shutdown_notify.clone();

    let server = tokio::spawn(async move {
        let _ = Server::builder()
            .add_service(AttestationVerificationServer::new(service))
            .serve_with_incoming_shutdown(
                tokio_stream::wrappers::TcpListenerStream::new(listener),
                shutdown_notify_copy.notified(),
            )
            .await;
    });

    // CA initialization should succeed - it should find the SPIFFE URI
    // among the DNS SAN entries.
    let mut client =
        AttestationVerificationClient::connect(format!("http://localhost:{}", port)).await.unwrap();
    client.generate_avs_signing_key(GenerateAvsSigningKeyRequest {}).await.unwrap();

    // Verify the trust domain is correct by issuing a certificate.
    let platform_endorsement = AmdSevSnpEndorsement { tee_certificate: get_milan_vcek() };
    let empty_variant: Variant = Variant::default();
    let endorsements = Endorsements {
        platform: Some(platform_endorsement.into()),
        initial: Some(empty_variant),
        ..Default::default()
    };

    static SUBJECT: &str = "example.com";
    let (csr_der, csr_key_pair) = generate_csr(SUBJECT).unwrap();
    let public_key_pem = pem::parse(csr_key_pair.public_key_pem()).unwrap();
    let public_key_der = public_key_pem.contents();

    let mut evidence = get_evidence();
    evidence.signed_user_data_certificate =
        create_signed_user_data_certificate(public_key_der, SIGNING_PRIVATE_KEY_HEX);

    let request = CertifyAttestationRequest {
        csr: csr_der,
        evidence: Some(evidence),
        endorsements: Some(endorsements),
        operator_info: Some(test_operator_info()),
        policy_hint: PolicyHint::DevelopmentCbCertificate.into(),
    };

    let response = call_certify_attestation(port, request).await.unwrap();
    assert_eq!(response.certificate_chain.len(), 3);
    let (expected_publisher, expected_role, expected_workload) =
        ("untrusted.com", "none", "unendorsed-development");

    validate_cert_chain(
        &response.certificate_chain,
        &csr_key_pair,
        &ExpectedSan::SpiffeUri(format!(
            "spiffe://{}/operator/google/encrypted-zone/publisher/{}/{}/workload/{}",
            MOCK_TCA_TRUST_DOMAIN, expected_publisher, expected_role, expected_workload
        )),
        ExpectedEku::None,
        &mock_tca_issuer_name(),
    );

    shutdown_notify.notify_waiters();
    server.await.unwrap();
}

#[tokio::test]
async fn test_certify_attestation_before_generate_key() {
    let service = AttestationVerificationService::new(None);

    let sockaddr = SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0);
    let listener = TcpListener::bind(sockaddr).await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let shutdown_notify = Arc::new(Notify::new());
    let shutdown_notify_copy = shutdown_notify.clone();

    let server = tokio::spawn(async move {
        let _ = Server::builder()
            .add_service(AttestationVerificationServer::new(service))
            .serve_with_incoming_shutdown(
                tokio_stream::wrappers::TcpListenerStream::new(listener),
                shutdown_notify_copy.notified(),
            )
            .await;
    });

    let mut client =
        AttestationVerificationClient::connect(format!("http://localhost:{}", port)).await.unwrap();

    // Attempt certify_attestation without calling generate_avs_signing_key first.
    static SUBJECT: &str = "example.com";
    let (csr_der, _) = generate_csr(SUBJECT).unwrap();
    let request = CertifyAttestationRequest {
        csr: csr_der,
        evidence: Some(get_evidence()),
        endorsements: Some(Endorsements::default()),
        ..Default::default()
    };

    let result = client.certify_attestation(request).await;
    match result {
        Ok(_) => panic!("Expected error because certificate authority is not initialized"),
        Err(e) => {
            assert_eq!(e.code(), tonic::Code::FailedPrecondition);
            assert!(e.to_string().contains("certificate authority has not been initialized"));
        }
    }

    shutdown_notify.notify_waiters();
    server.await.unwrap();
}

#[tokio::test]
async fn test_certify_attestation_stream_before_generate_key() {
    let service = AttestationVerificationService::new(None);

    let sockaddr = SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0);
    let listener = TcpListener::bind(sockaddr).await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let shutdown_notify = Arc::new(Notify::new());
    let shutdown_notify_copy = shutdown_notify.clone();

    let server = tokio::spawn(async move {
        let _ = Server::builder()
            .add_service(AttestationVerificationServer::new(service))
            .serve_with_incoming_shutdown(
                tokio_stream::wrappers::TcpListenerStream::new(listener),
                shutdown_notify_copy.notified(),
            )
            .await;
    });

    let mut client =
        AttestationVerificationClient::connect(format!("http://localhost:{}", port)).await.unwrap();

    let (tx, rx) = tokio::sync::mpsc::channel(2);
    tx.send(CertifyAttestationStreamRequest {
        request: Some(certify_attestation_stream_request::Request::ChallengeRequest(
            ChallengeRequest {},
        )),
    })
    .await
    .unwrap();

    let result =
        client.certify_attestation_stream(tokio_stream::wrappers::ReceiverStream::new(rx)).await;
    match result {
        Ok(_) => panic!("Expected error because certificate authority is not initialized"),
        Err(e) => {
            assert_eq!(e.code(), tonic::Code::FailedPrecondition);
            assert!(e.to_string().contains("certificate authority has not been initialized"));
        }
    }

    shutdown_notify.notify_waiters();
    server.await.unwrap();
}

fn construct_binding_payload(nonce: &[u8], public_key_der: &[u8]) -> Vec<u8> {
    let mut payload = Vec::new();
    payload.extend_from_slice(&(nonce.len() as u32).to_be_bytes());
    payload.extend_from_slice(nonce);
    payload.extend_from_slice(&(public_key_der.len() as u32).to_be_bytes());
    payload.extend_from_slice(public_key_der);
    payload
}

#[tokio::test]
async fn test_certify_attestation_stream_nonce_mismatch() {
    for mode in [ServerMode::SelfSigning, ServerMode::TcaMock] {
        let test_server = create_test_server_with_config(
            mode.clone(),
            policies::PoliciesConfig { include_development_policy: true },
        )
        .await
        .unwrap();

        let platform_endorsement = AmdSevSnpEndorsement { tee_certificate: get_milan_vcek() };
        let empty_variant: Variant = Variant::default();
        let endorsements = Endorsements {
            platform: Some(platform_endorsement.into()),
            initial: Some(empty_variant),
            ..Default::default()
        };

        static SUBJECT: &str = "example.com";
        let (csr_der, csr_key_pair) = generate_csr(SUBJECT).unwrap();
        let public_key_pem = pem::parse(csr_key_pair.public_key_pem()).unwrap();
        let public_key_der = public_key_pem.contents();

        let mut client = AttestationVerificationClient::connect(format!(
            "http://localhost:{}",
            test_server.port
        ))
        .await
        .unwrap();

        let (tx, rx) = tokio::sync::mpsc::channel(2);

        // Step 1: Send ChallengeRequest
        tx.send(CertifyAttestationStreamRequest {
            request: Some(certify_attestation_stream_request::Request::ChallengeRequest(
                ChallengeRequest {},
            )),
        })
        .await
        .unwrap();

        let mut response_stream = client
            .certify_attestation_stream(tokio_stream::wrappers::ReceiverStream::new(rx))
            .await
            .unwrap()
            .into_inner();

        // Step 2: Receive ChallengeResponse (nonce)
        let response = response_stream.next().await.unwrap().unwrap();
        let _nonce = match response.response {
            Some(certify_attestation_stream_response::Response::ChallengeResponse(r)) => r.nonce,
            _ => panic!("Expected challenge response"),
        };

        // Step 3: Provide a payload with a WRONG nonce.
        let wrong_nonce = vec![1u8; 32];
        let bound_payload = construct_binding_payload(&wrong_nonce, public_key_der);
        let mut evidence = get_evidence();
        evidence.signed_user_data_certificate =
            create_signed_user_data_certificate(&bound_payload, SIGNING_PRIVATE_KEY_HEX);

        // Step 4: Send Finish request
        tx.send(CertifyAttestationStreamRequest {
            request: Some(certify_attestation_stream_request::Request::CertifyRequest(
                CertifyAttestationRequest {
                    csr: csr_der,
                    evidence: Some(evidence),
                    endorsements: Some(endorsements),
                    operator_info: Some(test_operator_info()),
                    policy_hint: PolicyHint::DevelopmentCbCertificate.into(),
                },
            )),
        })
        .await
        .unwrap();

        // Step 5: Receive Final Response
        let response = response_stream.next().await;
        match response {
            Some(Ok(msg)) => match msg.response {
                Some(certify_attestation_stream_response::Response::CertifyResponse(_)) => {
                    panic!("Should have failed due to nonce mismatch")
                }
                _ => panic!("Expected final response or error"),
            },
            Some(Err(e)) => assert!(
                e.to_string().contains("quoted key does not match")
                    || e.to_string().contains("nonce mismatch")
            ),
            None => panic!("Stream closed early"),
        }

        test_server.shutdown_notify.notify_waiters();
        test_server.server.await.unwrap();
    }
}

#[tokio::test]
async fn test_certify_attestation_stream_success() {
    for mode in [ServerMode::SelfSigning, ServerMode::TcaMock] {
        let test_server = create_test_server_with_config(
            mode.clone(),
            policies::PoliciesConfig { include_development_policy: true },
        )
        .await
        .unwrap();

        let platform_endorsement = AmdSevSnpEndorsement { tee_certificate: get_milan_vcek() };
        let empty_variant: Variant = Variant::default();
        let endorsements = Endorsements {
            platform: Some(platform_endorsement.into()),
            initial: Some(empty_variant),
            ..Default::default()
        };

        static SUBJECT: &str = "example.com";
        let (csr_der, csr_key_pair) = generate_csr(SUBJECT).unwrap();
        let public_key_pem = pem::parse(csr_key_pair.public_key_pem()).unwrap();
        let public_key_der = public_key_pem.contents();

        let mut client = AttestationVerificationClient::connect(format!(
            "http://localhost:{}",
            test_server.port
        ))
        .await
        .unwrap();

        let (tx, rx) = tokio::sync::mpsc::channel(2);

        // Step 1: Send ChallengeRequest
        tx.send(CertifyAttestationStreamRequest {
            request: Some(certify_attestation_stream_request::Request::ChallengeRequest(
                ChallengeRequest {},
            )),
        })
        .await
        .unwrap();

        let mut response_stream = client
            .certify_attestation_stream(tokio_stream::wrappers::ReceiverStream::new(rx))
            .await
            .unwrap()
            .into_inner();

        // Step 2: Receive ChallengeResponse (nonce)
        let response = response_stream.next().await.unwrap().unwrap();
        let nonce = match response.response {
            Some(certify_attestation_stream_response::Response::ChallengeResponse(r)) => r.nonce,
            _ => panic!("Expected challenge response"),
        };

        // Step 3: Bind nonce and public key
        let bound_payload = construct_binding_payload(&nonce, public_key_der);
        let mut evidence = get_evidence();
        evidence.signed_user_data_certificate =
            create_signed_user_data_certificate(&bound_payload, SIGNING_PRIVATE_KEY_HEX);

        // Step 4: Send Finish request
        tx.send(CertifyAttestationStreamRequest {
            request: Some(certify_attestation_stream_request::Request::CertifyRequest(
                CertifyAttestationRequest {
                    csr: csr_der,
                    evidence: Some(evidence),
                    endorsements: Some(endorsements),
                    operator_info: Some(test_operator_info()),
                    policy_hint: PolicyHint::DevelopmentCbCertificate.into(),
                },
            )),
        })
        .await
        .unwrap();

        // Step 5: Receive Final Response
        let response = response_stream.next().await.unwrap().unwrap();
        let result = match response.response {
            Some(certify_attestation_stream_response::Response::CertifyResponse(r)) => r,
            _ => panic!("Expected final response"),
        };

        let (expected_chain_len, expected_trust_domain) = match mode {
            ServerMode::SelfSigning => (2, "prod.google.com.avs.pcit.goog"),
            ServerMode::TcaMock => (3, MOCK_TCA_TRUST_DOMAIN),
        };
        assert_eq!(
            result.certificate_chain.len(),
            expected_chain_len,
            "Expected {} certificates in chain for {:?} mode",
            expected_chain_len,
            mode
        );
        let (expected_publisher, expected_role, expected_workload) =
            ("untrusted.com", "none", "unendorsed-development");

        let expected_issuer = match mode {
            ServerMode::SelfSigning => self_signing_issuer_name(),
            ServerMode::TcaMock => mock_tca_issuer_name(),
        };
        validate_cert_chain(
            &result.certificate_chain,
            &csr_key_pair,
            &ExpectedSan::SpiffeUri(format!(
                "spiffe://{}/operator/google/encrypted-zone/publisher/{}/{}/workload/{}",
                expected_trust_domain, expected_publisher, expected_role, expected_workload
            )),
            ExpectedEku::None,
            &expected_issuer,
        );

        test_server.shutdown_notify.notify_waiters();
        test_server.server.await.unwrap();
    }
}

#[tokio::test]
async fn test_development_policy_disabled_fails() {
    for mode in [ServerMode::SelfSigning, ServerMode::TcaMock] {
        let test_server = create_test_server(mode.clone()).await.unwrap();

        let platform_endorsement = AmdSevSnpEndorsement { tee_certificate: get_milan_vcek() };
        let empty_variant: Variant = Variant::default();
        let endorsements = Endorsements {
            platform: Some(platform_endorsement.into()),
            initial: Some(empty_variant),
            ..Default::default()
        };

        static SUBJECT: &str = "example.com";
        let (csr_der, csr_key_pair) = generate_csr(SUBJECT).unwrap();
        let public_key_pem = pem::parse(csr_key_pair.public_key_pem()).unwrap();
        let public_key_der = public_key_pem.contents();

        let mut evidence = get_evidence();
        evidence.signed_user_data_certificate =
            create_signed_user_data_certificate(public_key_der, SIGNING_PRIVATE_KEY_HEX);

        for policy_hint in [
            PolicyHint::DevelopmentCbCertificate,
            PolicyHint::DevelopmentMtlsCbCertificate,
            PolicyHint::DevelopmentTlsCbCertificate,
        ] {
            let mut evidence = get_evidence();
            evidence.signed_user_data_certificate =
                create_signed_user_data_certificate(public_key_der, SIGNING_PRIVATE_KEY_HEX);

            let request = CertifyAttestationRequest {
                csr: csr_der.clone(),
                evidence: Some(evidence),
                endorsements: Some(endorsements.clone()),
                operator_info: Some(test_operator_info()),
                policy_hint: policy_hint.into(),
            };

            let result = call_certify_attestation(test_server.port, request).await;
            assert!(result.is_err());
            let err_msg = format!("{:?}", result.err().unwrap());
            assert!(
                err_msg.contains("policy not supported"),
                "Expected error 'policy not supported', got: {}",
                err_msg
            );
        }

        test_server.shutdown_notify.notify_waiters();
        test_server.server.await.unwrap();
    }
}

#[tokio::test]
async fn test_development_policy_enabled_succeeds() {
    for mode in [ServerMode::SelfSigning, ServerMode::TcaMock] {
        let test_server = create_test_server_with_config(
            mode.clone(),
            policies::PoliciesConfig { include_development_policy: true },
        )
        .await
        .unwrap();

        let platform_endorsement = AmdSevSnpEndorsement { tee_certificate: get_milan_vcek() };
        let empty_variant: Variant = Variant::default();
        let endorsements = Endorsements {
            platform: Some(platform_endorsement.into()),
            initial: Some(empty_variant),
            ..Default::default()
        };

        static SUBJECT: &str = "example.com";
        let (csr_der, csr_key_pair) = generate_csr(SUBJECT).unwrap();
        let public_key_pem = pem::parse(csr_key_pair.public_key_pem()).unwrap();
        let public_key_der = public_key_pem.contents();

        for (policy_hint, expected_eku, is_tls) in [
            (PolicyHint::DevelopmentCbCertificate, ExpectedEku::None, false),
            (PolicyHint::DevelopmentMtlsCbCertificate, ExpectedEku::ServerAndClientAuth, false),
            (PolicyHint::DevelopmentTlsCbCertificate, ExpectedEku::ServerAuth, true),
        ] {
            let mut evidence = get_evidence();
            evidence.signed_user_data_certificate =
                create_signed_user_data_certificate(public_key_der, SIGNING_PRIVATE_KEY_HEX);

            let request = CertifyAttestationRequest {
                csr: csr_der.clone(),
                evidence: Some(evidence),
                endorsements: Some(endorsements.clone()),
                operator_info: Some(test_operator_info()),
                policy_hint: policy_hint.into(),
            };

            let response = call_certify_attestation(test_server.port, request).await;

            let response = response.unwrap();
            let (expected_chain_len, expected_trust_domain) = match mode {
                ServerMode::SelfSigning => (2, "prod.google.com.avs.pcit.goog"),
                ServerMode::TcaMock => (3, MOCK_TCA_TRUST_DOMAIN),
            };
            assert_eq!(
                response.certificate_chain.len(),
                expected_chain_len,
                "Expected {} certificates in chain for {:?} mode",
                expected_chain_len,
                mode
            );
            let (expected_publisher, expected_role, expected_workload) =
                ("untrusted.com", "none", "unendorsed-development");

            let expected_san = if is_tls {
                ExpectedSan::DnsName(format!("encrypted-zone.google.{}", expected_trust_domain))
            } else {
                ExpectedSan::SpiffeUri(format!(
                    "spiffe://{}/operator/google/encrypted-zone/publisher/{}/{}/workload/{}",
                    expected_trust_domain, expected_publisher, expected_role, expected_workload
                ))
            };

            let expected_issuer = match mode {
                ServerMode::SelfSigning => self_signing_issuer_name(),
                ServerMode::TcaMock => mock_tca_issuer_name(),
            };
            validate_cert_chain(
                &response.certificate_chain,
                &csr_key_pair,
                &expected_san,
                expected_eku,
                &expected_issuer,
            );
        }

        test_server.shutdown_notify.notify_waiters();
        test_server.server.await.unwrap();
    }
}
