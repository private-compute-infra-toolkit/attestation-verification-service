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

// TODO: b/509861057 - Refactor unsafe Rust logic
use crate::csr::{ConnectionMode, ProvisionedIdentity};
use log::info;
use std::sync::Arc;
use std::sync::Mutex;
use tca_common::TcaClient;

const CERT_VALIDITY: i64 = 365;
const SEC_DAYS: i64 = 24 * 60 * 60;
const ISSUER_NAME: &str = "Attestation Verification Service";

// Trust domain for the SPIFFE identity in self-signed mode (no TCA).
const SELF_SIGNED_TRUST_DOMAIN: &str = "prod.google.com.avs.pcit.goog";

pub(crate) struct CertificateAuthority {
    ca_key: Mutex<KeyPair>,
    issuer_name: Mutex<*mut bssl_sys::X509_name_st>,
    // The certificate chain where the first element is the AVS CA cert,
    // followed by intermediate and/or root certs (if present).
    ca_cert_chain_der: Vec<Vec<u8>>,
    // Trust domain for the SPIFFE identity embedded in issued certificates.
    // For intermediate CAs this is extracted from the TCA-issued certificate's
    // SAN URI; for self-signed CAs this is SELF_SIGNED_TRUST_DOMAIN.
    trust_domain: String,
}

// TODO: encapsulate x509 with a rust struct
// and implement Drop train similar to what is done for `KeyPair`
// to make cleanup logic easier.
impl CertificateAuthority {
    pub(crate) async fn new_intermediate(tca_client: Arc<dyn TcaClient>) -> anyhow::Result<Self> {
        // Generate the keypair and CSR. The locally-constructed subject name
        // is only needed for the CSR and is freed immediately after.
        let (ca_key, csr_der) = unsafe {
            let subject_name_ptr = Self::create_issuer_x509_name(ISSUER_NAME)?;
            let ca_key = match Self::create_ca_keypair() {
                Ok(k) => k,
                Err(e) => {
                    bssl_sys::X509_NAME_free(subject_name_ptr);
                    return Err(e);
                }
            };
            let csr_der = match Self::create_ca_csr(&ca_key, subject_name_ptr) {
                Ok(c) => {
                    bssl_sys::X509_NAME_free(subject_name_ptr);
                    c
                }
                Err(e) => {
                    bssl_sys::X509_NAME_free(subject_name_ptr);
                    return Err(e);
                }
            };
            (ca_key, csr_der)
        };

        let tca_common::CertificateChain(cert_chain) = tca_client
            .issue_certificate(tca_common::Csr(csr_der))
            .await
            .map_err(anyhow::Error::new)?;

        if cert_chain.is_empty() {
            anyhow::bail!("TCA returned empty certificate chain");
        }

        info!("TCA returned a certificate chain with {} certificates:", cert_chain.len());
        for (i, tca_common::Certificate(cert_der)) in cert_chain.iter().enumerate() {
            info!("Certificate #{} (DER encoded, {} bytes):", i, cert_der.len());
            info!("{}", cert_der.iter().map(|b| format!("{:02x}", b)).collect::<String>());
        }

        let ca_cert_chain_der: Vec<Vec<u8>> =
            cert_chain.into_iter().map(|tca_common::Certificate(c)| c).collect();

        let trust_domain = Self::extract_trust_domain_from_cert(&ca_cert_chain_der[0])?;
        info!("Extracted trust domain from TCA-issued certificate: {}", trust_domain);

        // Use the Subject DN from the TCA-issued certificate as the issuer
        // name for leaf certs. Per RFC 5280 4.1.2.4, the leaf certificate's
        // Issuer DN must exactly match the signing CA certificate's Subject DN.
        let issuer_name_ptr = Self::extract_subject_name_from_cert(&ca_cert_chain_der[0])?;

        Ok(Self {
            // Encapsulate `ca_key` and `issuer_name_ptr` in mutexes so they can be
            // safely moved across async boundaries.
            ca_key: Mutex::new(ca_key),
            issuer_name: Mutex::new(issuer_name_ptr),
            ca_cert_chain_der,
            trust_domain,
        })
    }

    pub(crate) fn new_root() -> anyhow::Result<Self> {
        unsafe {
            let ca_key = Self::create_ca_keypair()?;
            let issuer_name_ptr = Self::create_issuer_x509_name(ISSUER_NAME)?;

            let x509 = match Self::create_ca_x509(&ca_key, issuer_name_ptr) {
                Ok(x) => x,
                Err(e) => {
                    bssl_sys::X509_NAME_free(issuer_name_ptr);
                    return Err(e);
                }
            };

            let ca_cert_der = match Self::x509_to_der(x509) {
                Ok(der) => der,
                Err(e) => {
                    bssl_sys::X509_NAME_free(issuer_name_ptr);
                    bssl_sys::X509_free(x509);
                    return Err(e);
                }
            };
            bssl_sys::X509_free(x509);

            Ok(Self {
                ca_key: Mutex::new(ca_key),
                issuer_name: Mutex::new(issuer_name_ptr),
                ca_cert_chain_der: vec![ca_cert_der],
                trust_domain: SELF_SIGNED_TRUST_DOMAIN.to_string(),
            })
        }
    }

    pub(crate) fn get_ca_cert_chain_der(&self) -> &[Vec<u8>] {
        &self.ca_cert_chain_der
    }

    pub(crate) fn generate_certificate(
        &self,
        identity: &ProvisionedIdentity,
    ) -> anyhow::Result<Vec<u8>> {
        unsafe {
            let x509 = bssl_sys::X509_new();
            if x509.is_null() {
                anyhow::bail!("Failed to create X509 object.");
            }

            if let Err(e) = Self::set_x509_version(x509) {
                bssl_sys::X509_free(x509);
                return Err(e);
            }
            if let Err(e) = Self::set_x509_serial_random(x509) {
                bssl_sys::X509_free(x509);
                return Err(e);
            }

            let issuer_name = match self.issuer_name.lock() {
                Ok(issuer_name) => issuer_name,
                Err(e) => {
                    bssl_sys::X509_free(x509);
                    anyhow::bail!("Issuer name mutex poisoned: {e}");
                }
            };

            if bssl_sys::X509_set_issuer_name(x509, *issuer_name) != 1 {
                bssl_sys::X509_free(x509);
                anyhow::bail!("Failed to set issuer name");
            }

            if bssl_sys::X509_set_pubkey(x509, identity.public_key.key_pair) != 1 {
                bssl_sys::X509_free(x509);
                anyhow::bail!("Failed to set public key");
            }

            let ext = match self.create_san_extension(identity) {
                Ok(ext) => ext,
                Err(e) => {
                    bssl_sys::X509_free(x509);
                    return Err(e);
                }
            };
            if ext.is_null() {
                bssl_sys::X509_free(x509);
                anyhow::bail!("Failed to create SAN extension");
            }
            if bssl_sys::X509_add_ext(/* x= */ x509, /* ext= */ ext, /* loc= */ -1) != 1 {
                bssl_sys::X509_EXTENSION_free(ext);
                bssl_sys::X509_free(x509);
                anyhow::bail!("Failed to add SAN extension");
            }
            bssl_sys::X509_EXTENSION_free(ext);

            if let Err(e) = Self::set_x509_extended_key_usage(x509, &identity.connection_mode) {
                bssl_sys::X509_free(x509);
                return Err(e);
            }

            if let Err(e) = Self::set_x509_leaf_basic_constraints(x509) {
                bssl_sys::X509_free(x509);
                return Err(e);
            }

            if let Err(e) = Self::set_x509_key_usage(x509) {
                bssl_sys::X509_free(x509);
                return Err(e);
            }

            if let Err(e) = Self::set_x509_validity(x509, CERT_VALIDITY) {
                bssl_sys::X509_free(x509);
                return Err(e);
            }

            let ca_key = match self.ca_key.lock() {
                Ok(ca_key) => ca_key,
                Err(e) => {
                    bssl_sys::X509_free(x509);
                    anyhow::bail!("CA key mutex poisoned: {e}");
                }
            };

            if let Err(e) = Self::sign_x509(x509, &ca_key) {
                bssl_sys::X509_free(x509);
                return Err(e);
            }

            let cert_der = match Self::x509_to_der(x509) {
                Ok(p) => p,
                Err(e) => {
                    bssl_sys::X509_free(x509);
                    return Err(e);
                }
            };
            bssl_sys::X509_free(x509);
            Ok(cert_der)
        }
    }

    fn create_ca_csr(
        key_pair: &KeyPair,
        subject_name: *mut bssl_sys::X509_name_st,
    ) -> anyhow::Result<Vec<u8>> {
        unsafe {
            let req = bssl_sys::X509_REQ_new();
            if req.is_null() {
                anyhow::bail!("Failed to create X509_REQ");
            }

            if bssl_sys::X509_REQ_set_version(req, 0) != 1 {
                bssl_sys::X509_REQ_free(req);
                anyhow::bail!("Failed to set CSR version");
            }

            if bssl_sys::X509_REQ_set_subject_name(req, subject_name) != 1 {
                bssl_sys::X509_REQ_free(req);
                anyhow::bail!("Failed to set CSR subject");
            }

            if bssl_sys::X509_REQ_set_pubkey(req, key_pair.key_pair) != 1 {
                bssl_sys::X509_REQ_free(req);
                anyhow::bail!("Failed to set CSR pubkey");
            }

            if bssl_sys::X509_REQ_sign(req, key_pair.key_pair, bssl_sys::EVP_sha256()) <= 0 {
                bssl_sys::X509_REQ_free(req);
                anyhow::bail!("Failed to sign CSR");
            }

            let len = bssl_sys::i2d_X509_REQ(req, std::ptr::null_mut());
            if len < 0 {
                bssl_sys::X509_REQ_free(req);
                anyhow::bail!("Failed to determine CSR DER encoding length");
            }

            let mut csr_der = vec![0u8; len as usize];
            let mut p = csr_der.as_mut_ptr();
            let written = bssl_sys::i2d_X509_REQ(req, &mut p);
            bssl_sys::X509_REQ_free(req);

            if written < 0 {
                anyhow::bail!("Failed to encode CSR to DER");
            }

            Ok(csr_der)
        }
    }

    fn create_ca_keypair() -> anyhow::Result<KeyPair> {
        unsafe {
            let rsa = bssl_sys::RSA_new();
            if rsa.is_null() {
                anyhow::bail!("Failed to create RSA struct.");
            }
            let big_e = bssl_sys::BN_new();
            if big_e.is_null() {
                bssl_sys::RSA_free(rsa);
                anyhow::bail!("Failed to create BIGNUM for exponent.");
            }
            // `65537` is he Fermat number F4 = 65537 = 2^16 + 1.
            // There is bssl_sys::RSA_F4 constant but we need to conversion to use it.
            // as the function expectes u64 and the constant is i32 (we need to handle the
            // error).
            if bssl_sys::BN_set_word(big_e, /* w= */ 65537) != 1 {
                bssl_sys::BN_free(big_e);
                bssl_sys::RSA_free(rsa);
                anyhow::bail!("Failed to set exponent value");
            }
            if bssl_sys::RSA_generate_key_ex(
                rsa,
                /* bits= */ 2048,
                big_e,
                std::ptr::null_mut(),
            ) != 1
            {
                bssl_sys::BN_free(big_e);
                bssl_sys::RSA_free(rsa);
                anyhow::bail!("Failed to generate RSA key pair.");
            }
            bssl_sys::BN_free(big_e);

            let ca_key_ptr = bssl_sys::EVP_PKEY_new();
            if ca_key_ptr.is_null() {
                bssl_sys::RSA_free(rsa);
                anyhow::bail!("Failed to create PKey for Certificate Authority.");
            }

            // `EVP_PKEY_assign_RSA()` takes ownership of `rsa` so we don't need to free it.
            if bssl_sys::EVP_PKEY_assign_RSA(ca_key_ptr, rsa) != 1 {
                bssl_sys::EVP_PKEY_free(ca_key_ptr);
                anyhow::bail!("Failed to assign RSA to PKey.");
            }
            Ok(KeyPair::new(ca_key_ptr))
        }
    }

    fn create_issuer_x509_name(name: &str) -> anyhow::Result<*mut bssl_sys::X509_name_st> {
        unsafe {
            let issuer_name_ptr = bssl_sys::X509_NAME_new();
            if issuer_name_ptr.is_null() {
                anyhow::bail!("Failed to create X509_NAME for issuer");
            }
            let cn_field = match std::ffi::CString::new("CN") {
                Ok(s) => s,
                Err(e) => {
                    bssl_sys::X509_NAME_free(issuer_name_ptr);
                    return Err(anyhow::anyhow!(e));
                }
            };
            let cn_value = match std::ffi::CString::new(name) {
                Ok(s) => s,
                Err(e) => {
                    bssl_sys::X509_NAME_free(issuer_name_ptr);
                    return Err(anyhow::anyhow!(e));
                }
            };
            if bssl_sys::X509_NAME_add_entry_by_txt(
                issuer_name_ptr,
                cn_field.as_ptr(),
                bssl_sys::MBSTRING_ASC,
                cn_value.as_ptr() as *const u8,
                /* len= */ -1,
                /* loc= */ -1,
                /* set= */ 0,
            ) != 1
            {
                bssl_sys::X509_NAME_free(issuer_name_ptr);
                anyhow::bail!("Failed to create issuer name.");
            }
            Ok(issuer_name_ptr)
        }
    }

    fn create_ca_x509(
        key_pair: &KeyPair,
        issuer_name: *mut bssl_sys::X509_name_st,
    ) -> anyhow::Result<*mut bssl_sys::X509> {
        unsafe {
            let x509 = bssl_sys::X509_new();
            if x509.is_null() {
                anyhow::bail!("Failed to create X509 for CA cert.");
            }

            if let Err(e) = Self::set_x509_version(x509) {
                bssl_sys::X509_free(x509);
                return Err(e);
            }

            let serial_number = bssl_sys::ASN1_INTEGER_new();
            if serial_number.is_null() {
                bssl_sys::X509_free(x509);
                anyhow::bail!("Failed to create ASN1_INTEGER");
            }

            bssl_sys::ASN1_INTEGER_set(serial_number, 1);
            if bssl_sys::X509_set_serialNumber(x509, serial_number) != 1 {
                bssl_sys::ASN1_INTEGER_free(serial_number);
                bssl_sys::X509_free(x509);
                anyhow::bail!("Failed to set CA cert serial number");
            }
            bssl_sys::ASN1_INTEGER_free(serial_number);

            if bssl_sys::X509_set_subject_name(x509, issuer_name) != 1 {
                bssl_sys::X509_free(x509);
                anyhow::bail!("Failed to set CA cert subject name");
            }
            if bssl_sys::X509_set_issuer_name(x509, issuer_name) != 1 {
                bssl_sys::X509_free(x509);
                anyhow::bail!("Failed to set CA cert issuer name");
            }

            if bssl_sys::X509_set_pubkey(x509, key_pair.key_pair) != 1 {
                bssl_sys::X509_free(x509);
                anyhow::bail!("Failed to set CA cert public key");
            }

            if let Err(e) = Self::set_x509_validity(x509, CERT_VALIDITY) {
                bssl_sys::X509_free(x509);
                return Err(e);
            }
            if let Err(e) = Self::set_x509_ca_basic_constraints(x509) {
                bssl_sys::X509_free(x509);
                return Err(e);
            }
            if let Err(e) = Self::sign_x509(x509, key_pair) {
                bssl_sys::X509_free(x509);
                return Err(e);
            }

            Ok(x509)
        }
    }

    fn set_x509_version(x509: *mut bssl_sys::X509) -> anyhow::Result<()> {
        unsafe {
            if bssl_sys::X509_set_version(x509, 2) != 1 {
                anyhow::bail!("Failed to set cert version");
            }
        }
        Ok(())
    }

    fn set_x509_validity(x509: *mut bssl_sys::X509, days: i64) -> anyhow::Result<()> {
        unsafe {
            let not_before = bssl_sys::X509_getm_notBefore(x509);
            if bssl_sys::X509_gmtime_adj(not_before, 0).is_null() {
                anyhow::bail!("Failed to set notBefore");
            }
            let not_after = bssl_sys::X509_getm_notAfter(x509);
            // We could use `Duration::from_days(days)::as_sec()`, but this
            // requires conversion from u64 to i64 and requires error checking.
            if bssl_sys::X509_gmtime_adj(not_after, days * SEC_DAYS).is_null() {
                anyhow::bail!("Failed to set notAfter");
            }
        }
        Ok(())
    }

    // Add a BasicConstraints extension with CA:TRUE (critical) to mark the
    // certificate as a CA capable of signing other certificates.
    // See RFC 5280 Section 4.2.1.9:
    // https://datatracker.ietf.org/doc/html/rfc5280#section-4.2.1.9
    fn set_x509_ca_basic_constraints(x509: *mut bssl_sys::X509) -> anyhow::Result<()> {
        unsafe {
            let basic_constraints = bssl_sys::BASIC_CONSTRAINTS_new();
            if basic_constraints.is_null() {
                anyhow::bail!("Failed to create BASIC_CONSTRAINTS");
            }

            if let Some(bc) = basic_constraints.as_mut() {
                bc.ca = 1;
            } else {
                // This case should be impossible due to the is_null() check above,
                // but handling it defensively.
                bssl_sys::BASIC_CONSTRAINTS_free(basic_constraints);
                anyhow::bail!("Failed to get mutable reference to BASIC_CONSTRAINTS");
            }

            // Create a Basic Constraints extension to be added to a CA certificate,
            // marking the certificate as capable of issuing other certificates.
            let ext = bssl_sys::X509_EXTENSION_create_by_NID(
                std::ptr::null_mut(),            // ext, optional existing extension
                bssl_sys::NID_basic_constraints, // NID for the extension type
                1,                               // Mark this extension as critical.
                basic_constraints as *mut _,     // Pointer to the extension data
            );
            if ext.is_null() {
                bssl_sys::BASIC_CONSTRAINTS_free(basic_constraints);
                anyhow::bail!("Failed to create basic constraints extension");
            }
            if bssl_sys::X509_add_ext(x509, ext, -1) != 1 {
                bssl_sys::X509_EXTENSION_free(ext);
                bssl_sys::BASIC_CONSTRAINTS_free(basic_constraints);
                anyhow::bail!("Failed to add basic constraints extension");
            }
            bssl_sys::X509_EXTENSION_free(ext);
            bssl_sys::BASIC_CONSTRAINTS_free(basic_constraints);
        }
        Ok(())
    }

    // Sets BasicConstraints to CA:FALSE (critical) to ensure the certificate
    // cannot be used as a CA certificate.
    // See RFC 5280 Section 4.2.1.9:
    // https://datatracker.ietf.org/doc/html/rfc5280#section-4.2.1.9
    fn set_x509_leaf_basic_constraints(x509: *mut bssl_sys::X509) -> anyhow::Result<()> {
        let value = std::ffi::CString::new("critical,CA:FALSE")
            .map_err(|_| anyhow::anyhow!("Failed to create BasicConstraints value string"))?;
        unsafe {
            let ext = bssl_sys::X509V3_EXT_nconf_nid(
                /* conf= */ std::ptr::null_mut(),
                /* ctx= */ std::ptr::null(),
                /* ext_nid= */ bssl_sys::NID_basic_constraints,
                /* value= */ value.as_ptr(),
            );
            if ext.is_null() {
                anyhow::bail!("Failed to create leaf BasicConstraints extension");
            }
            if bssl_sys::X509_add_ext(x509, ext, -1) != 1 {
                bssl_sys::X509_EXTENSION_free(ext);
                anyhow::bail!("Failed to add leaf BasicConstraints extension");
            }
            bssl_sys::X509_EXTENSION_free(ext);
        }
        Ok(())
    }

    // Sets Key Usage to digitalSignature (critical).
    // digitalSignature is required for the TLS 1.3 handshake signature.
    // See RFC 5280 Section 4.2.1.3:
    // https://datatracker.ietf.org/doc/html/rfc5280#section-4.2.1.3
    fn set_x509_key_usage(x509: *mut bssl_sys::X509) -> anyhow::Result<()> {
        let value = std::ffi::CString::new("critical,digitalSignature")
            .map_err(|_| anyhow::anyhow!("Failed to create Key Usage value string"))?;
        unsafe {
            let ext = bssl_sys::X509V3_EXT_nconf_nid(
                /* conf= */ std::ptr::null_mut(),
                /* ctx= */ std::ptr::null(),
                /* ext_nid= */ bssl_sys::NID_key_usage,
                /* value= */ value.as_ptr(),
            );
            if ext.is_null() {
                anyhow::bail!("Failed to create Key Usage extension");
            }
            if bssl_sys::X509_add_ext(x509, ext, -1) != 1 {
                bssl_sys::X509_EXTENSION_free(ext);
                anyhow::bail!("Failed to add Key Usage extension");
            }
            bssl_sys::X509_EXTENSION_free(ext);
        }
        Ok(())
    }

    fn sign_x509(x509: *mut bssl_sys::X509, key: &KeyPair) -> anyhow::Result<()> {
        unsafe {
            if bssl_sys::X509_sign(x509, key.key_pair, bssl_sys::EVP_sha256()) <= 0 {
                anyhow::bail!("Failed to sign certificate");
            }
        }
        Ok(())
    }

    // Parses a DER-encoded certificate and returns a duplicated copy of its
    // Subject DN. The caller takes ownership and must free the returned
    // pointer with `X509_NAME_free` when it is no longer needed.
    fn extract_subject_name_from_cert(
        cert_der: &[u8],
    ) -> anyhow::Result<*mut bssl_sys::X509_name_st> {
        let mut ptr = cert_der.as_ptr();
        // Safety: ptr and len correctly describe the cert_der slice.
        let x509 =
            unsafe { bssl_sys::d2i_X509(std::ptr::null_mut(), &mut ptr, cert_der.len() as i64) };
        if x509.is_null() {
            anyhow::bail!("Failed to parse certificate for subject name extraction");
        }

        // Safety: x509 is a valid, non-null X509 pointer from d2i_X509.
        let subject_name = unsafe { bssl_sys::X509_get_subject_name(x509) };
        if subject_name.is_null() {
            unsafe { bssl_sys::X509_free(x509) };
            anyhow::bail!("Certificate has no subject name");
        }

        // Safety: subject_name is valid and owned by x509. X509_NAME_dup
        // produces an independent copy so x509 can be freed afterwards.
        let dup = unsafe { bssl_sys::X509_NAME_dup(subject_name) };
        unsafe { bssl_sys::X509_free(x509) };

        if dup.is_null() {
            anyhow::bail!("Failed to duplicate subject name");
        }

        Ok(dup)
    }

    // Parses the DER-encoded certificate, extracts the raw SAN extension data,
    // and searches for a `spiffe://` URI and returns the trust domain (the
    // authority component before the first `/`).
    fn extract_trust_domain_from_cert(cert_der: &[u8]) -> anyhow::Result<String> {
        let san_bytes = unsafe {
            let mut ptr = cert_der.as_ptr();
            let x509 = bssl_sys::d2i_X509(std::ptr::null_mut(), &mut ptr, cert_der.len() as i64);
            if x509.is_null() {
                anyhow::bail!("Failed to parse certificate for trust domain extraction");
            }

            let ext_idx = bssl_sys::X509_get_ext_by_NID(x509, bssl_sys::NID_subject_alt_name, -1);
            if ext_idx < 0 {
                bssl_sys::X509_free(x509);
                anyhow::bail!("Certificate does not contain a Subject Alternative Name extension");
            }

            let ext = bssl_sys::X509_get_ext(x509, ext_idx);
            if ext.is_null() {
                bssl_sys::X509_free(x509);
                anyhow::bail!("Failed to retrieve SAN extension");
            }

            let octet_string = bssl_sys::X509_EXTENSION_get_data(ext);
            if octet_string.is_null() {
                bssl_sys::X509_free(x509);
                anyhow::bail!("SAN extension has no data");
            }

            let data_ptr = bssl_sys::ASN1_STRING_get0_data(octet_string as *const _);
            let data_len = bssl_sys::ASN1_STRING_length(octet_string as *const _);

            if data_ptr.is_null() || data_len <= 0 {
                bssl_sys::X509_free(x509);
                anyhow::bail!("SAN extension data is empty");
            }

            let san_bytes = std::slice::from_raw_parts(data_ptr, data_len as usize).to_vec();
            bssl_sys::X509_free(x509);
            san_bytes
        };
        Self::extract_spiffe_trust_domain(&san_bytes)
    }

    // Searches the raw SAN extension bytes for a `spiffe://` URI and returns
    // the trust domain (the authority component before the first `/`).
    // Returns an error if multiple or no SPIFFE URIs are found.
    fn extract_spiffe_trust_domain(san_bytes: &[u8]) -> anyhow::Result<String> {
        let san_str = String::from_utf8_lossy(san_bytes);
        let matches: Vec<&str> = san_str
            .match_indices("spiffe://")
            .map(|(idx, _)| {
                let rest = &san_str[idx..];
                // Each SPIFFE URI ends at the first non-printable ASCII byte
                // or end of string.
                let end = rest.find(|c: char| !c.is_ascii_graphic()).unwrap_or(rest.len());
                &rest[..end]
            })
            .collect();

        if matches.is_empty() {
            anyhow::bail!("No SPIFFE URI found in SAN extension");
        }
        if matches.len() > 1 {
            anyhow::bail!("Multiple SPIFFE URIs found in SAN extension: {:?}", matches);
        }

        let uri = matches[0];
        let rest = uri.strip_prefix("spiffe://").unwrap();
        let trust_domain = rest.split('/').next().unwrap_or(rest);
        if trust_domain.is_empty() {
            anyhow::bail!("SPIFFE URI has an empty trust domain: {}", uri);
        }
        Ok(trust_domain.to_string())
    }

    /// Dispatches SAN extension creation based on the connection mode.
    /// TLS mode uses a DNS SAN; all other modes use a SPIFFE URI SAN.
    fn create_san_extension(
        &self,
        identity: &ProvisionedIdentity,
    ) -> anyhow::Result<*mut bssl_sys::X509_EXTENSION> {
        match identity.connection_mode {
            ConnectionMode::Tls => self.create_dns_extension(identity),
            _ => self.create_spiffe_extension(identity),
        }
    }

    fn create_spiffe_extension(
        &self,
        identity: &ProvisionedIdentity,
    ) -> anyhow::Result<*mut bssl_sys::X509_EXTENSION> {
        // Add SPIFFE ID as `subject_alt_name` (OID 2.5.29.17) extension
        // and URI type.
        let spiffe_id = format!(
            "URI:spiffe://{}/operator/{}/{}/publisher/{}/{}/workload/{}",
            self.trust_domain,
            identity.operator_domain,
            identity.operator_role,
            identity.publisher_domain,
            identity.publisher_role,
            identity.workload_name,
        );
        let ext_value = std::ffi::CString::new(spiffe_id)
            .map_err(|_| anyhow::anyhow!("Cannot create SPIFFE string"))?;
        let ext = unsafe {
            bssl_sys::X509V3_EXT_nconf_nid(
                /* conf= */ std::ptr::null_mut(),
                /* ctx= */ std::ptr::null(),
                /* ext_nid= */ bssl_sys::NID_subject_alt_name,
                /* value= */ ext_value.as_ptr(),
            )
        };
        Ok(ext)
    }

    fn create_dns_extension(
        &self,
        identity: &ProvisionedIdentity,
    ) -> anyhow::Result<*mut bssl_sys::X509_EXTENSION> {
        // Add a DNS name as `subject_alt_name` (OID 2.5.29.17) extension
        // in the format: <operator_role>.<operator_domain>.<trust_domain>.
        let dns_name = format!(
            "DNS:{}.{}.{}",
            identity.operator_role, identity.operator_domain, self.trust_domain,
        );
        let ext_value = std::ffi::CString::new(dns_name)
            .map_err(|_| anyhow::anyhow!("Cannot create DNS SAN string"))?;
        let ext = unsafe {
            bssl_sys::X509V3_EXT_nconf_nid(
                /* conf= */ std::ptr::null_mut(),
                /* ctx= */ std::ptr::null(),
                /* ext_nid= */ bssl_sys::NID_subject_alt_name,
                /* value= */ ext_value.as_ptr(),
            )
        };
        Ok(ext)
    }

    // Adds the Extended Key Usage extension based on the connection mode.
    fn set_x509_extended_key_usage(
        x509: *mut bssl_sys::X509,
        connection_mode: &ConnectionMode,
    ) -> anyhow::Result<()> {
        let eku_str = match connection_mode {
            ConnectionMode::Unrestricted => return Ok(()),
            ConnectionMode::Mtls => "serverAuth,clientAuth",
            ConnectionMode::Tls => "serverAuth",
        };
        let eku_value = std::ffi::CString::new(eku_str)
            .map_err(|_| anyhow::anyhow!("Failed to create EKU value string"))?;
        unsafe {
            let ext = bssl_sys::X509V3_EXT_nconf_nid(
                /* conf= */ std::ptr::null_mut(),
                /* ctx= */ std::ptr::null(),
                /* ext_nid= */ bssl_sys::NID_ext_key_usage,
                /* value= */ eku_value.as_ptr(),
            );
            if ext.is_null() {
                anyhow::bail!("Failed to create Extended Key Usage extension");
            }
            if bssl_sys::X509_add_ext(/* x= */ x509, /* ext= */ ext, /* loc= */ -1) != 1 {
                bssl_sys::X509_EXTENSION_free(ext);
                anyhow::bail!("Failed to add Extended Key Usage extension");
            }
            bssl_sys::X509_EXTENSION_free(ext);
        }
        Ok(())
    }

    fn set_x509_serial_random(x509: *mut bssl_sys::X509) -> anyhow::Result<()> {
        unsafe {
            let serial_number = bssl_sys::ASN1_INTEGER_new();
            if serial_number.is_null() {
                bssl_sys::ASN1_INTEGER_free(serial_number);
                anyhow::bail!("Failed to create ASN1_INTEGER");
            }
            let big_num = bssl_sys::BN_new();
            if big_num.is_null() {
                bssl_sys::BN_free(big_num);
                bssl_sys::ASN1_INTEGER_free(serial_number);
                anyhow::bail!("Failed to create BigNum for serial");
            }

            // Serial number is a non-negative number that is 160-bit or less.
            // We ask for 152-bit random number to avoid interpreting the number as
            // negative.
            if bssl_sys::BN_rand(
                big_num,
                152,
                bssl_sys::BN_RAND_TOP_ONE,
                bssl_sys::BN_RAND_BOTTOM_ANY,
            ) != 1
            {
                bssl_sys::BN_free(big_num);
                bssl_sys::ASN1_INTEGER_free(serial_number);
                anyhow::bail!("Failed to generate random BigNum for serial");
            }
            if bssl_sys::BN_to_ASN1_INTEGER(big_num, serial_number).is_null() {
                bssl_sys::BN_free(big_num);
                bssl_sys::ASN1_INTEGER_free(serial_number);
                anyhow::bail!("Failed to convert BigNum to ASN1_INTEGER");
            }
            bssl_sys::BN_free(big_num);
            if bssl_sys::X509_set_serialNumber(x509, serial_number) != 1 {
                bssl_sys::ASN1_INTEGER_free(serial_number);
                anyhow::bail!("Failed to set serial number");
            }
            bssl_sys::ASN1_INTEGER_free(serial_number);
        }
        Ok(())
    }

    // Helper function to encode X509 to DER
    fn x509_to_der(x509: *mut bssl_sys::X509) -> anyhow::Result<Vec<u8>> {
        unsafe {
            // First call with null to determine the required buffer length.
            let len = bssl_sys::i2d_X509(x509, std::ptr::null_mut());
            if len < 0 {
                anyhow::bail!("Failed to determine DER encoding length");
            }
            // Allocate a buffer and encode the certificate.
            let mut cert_der = vec![0u8; len as usize];
            let mut p = cert_der.as_mut_ptr();
            let written = bssl_sys::i2d_X509(x509, &mut p);
            if written < 0 {
                anyhow::bail!("Failed to encode X509 to DER");
            }
            Ok(cert_der)
        }
    }
}

pub(crate) struct KeyPair {
    key_pair: *mut bssl_sys::EVP_PKEY,
}

impl Drop for CertificateAuthority {
    fn drop(&mut self) {
        unsafe {
            if let Ok(issuer_name) = self.issuer_name.lock() {
                bssl_sys::X509_NAME_free(*issuer_name);
            } else {
                // Log error, but can't do much more in Drop
                eprintln!("Error locking issuer_name mutex in Drop");
            }
        }
    }
}

unsafe impl Send for CertificateAuthority {}
unsafe impl Sync for CertificateAuthority {}

impl KeyPair {
    pub(crate) fn new(key_pair: *mut bssl_sys::EVP_PKEY) -> Self {
        Self { key_pair }
    }
    /// Creates a `KeyPair` from DER-encoded public key bytes.
    pub(crate) fn from_bytes(bytes: &[u8]) -> anyhow::Result<Self> {
        unsafe {
            let mut ptr = bytes.as_ptr();
            let pkey = bssl_sys::d2i_PUBKEY(std::ptr::null_mut(), &mut ptr, bytes.len() as i64);
            if pkey.is_null() {
                anyhow::bail!("failed to parse public key from DER bytes");
            }
            Ok(Self { key_pair: pkey })
        }
    }
}

impl Drop for KeyPair {
    fn drop(&mut self) {
        unsafe {
            bssl_sys::EVP_PKEY_free(self.key_pair);
        }
    }
}

unsafe impl Send for KeyPair {}
unsafe impl Sync for KeyPair {}

impl PartialEq for KeyPair {
    fn eq(&self, other: &Self) -> bool {
        // EVP_PKEY_cmp returns 1 if the keys are equal, 0 if not, and a negative value
        // on error.
        unsafe { bssl_sys::EVP_PKEY_cmp(self.key_pair, other.key_pair) == 1 }
    }
}

impl Eq for KeyPair {}
