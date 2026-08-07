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

//! Validated operator identity domain model.
//!
//! Provides defense-in-depth against SAN forgery and path injection
//! vulnerabilities by enforcing strict domain name and single-segment role
//! validation on ingress.

/// Maximum allowable total length for `operator_domain`.
const MAX_DOMAIN_LEN: usize = 253;

/// Maximum allowable length for an individual label within `operator_domain` or
/// `operator_role`.
const MAX_LABEL_OR_ROLE_LEN: usize = 63;

use thiserror::Error;

#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum OperatorInfoError {
    #[error("operator_domain must not be empty")]
    EmptyDomain,
    #[error("operator_domain length ({len}) exceeds maximum allowed ({MAX_DOMAIN_LEN})")]
    DomainTooLong { len: usize },
    #[error(
        "operator_domain contains an empty label (e.g. leading, trailing, or consecutive dots)"
    )]
    InvalidDomainLabelEmpty,
    #[error("operator_domain label '{label}' length ({len}) exceeds maximum allowed ({MAX_LABEL_OR_ROLE_LEN})")]
    InvalidDomainLabelTooLong { label: String, len: usize },
    #[error("operator_domain contains invalid character '{char}' (allowed: [a-zA-Z0-9-_])")]
    InvalidDomainCharacter { char: char },
    #[error("operator_domain label '{label}' must not start or end with a hyphen")]
    DomainLabelHyphenBoundary { label: String },
    #[error("operator_role must not be empty")]
    EmptyRole,
    #[error("operator_role length ({len}) exceeds maximum allowed ({MAX_LABEL_OR_ROLE_LEN})")]
    RoleTooLong { len: usize },
    #[error("operator_role contains invalid character '{char}' (allowed: [a-zA-Z0-9-_])")]
    InvalidRoleCharacter { char: char },
    #[error("operator_role '{0}' must not start or end with a hyphen")]
    RoleHyphenBoundary(String),
}

impl From<OperatorInfoError> for tonic::Status {
    fn from(err: OperatorInfoError) -> Self {
        tonic::Status::invalid_argument(err.to_string())
    }
}

fn is_valid_char(c: char) -> bool {
    c.is_ascii_alphanumeric() || c == '-' || c == '_'
}

fn validate_domain(domain: &str) -> Result<(), OperatorInfoError> {
    if domain.is_empty() {
        return Err(OperatorInfoError::EmptyDomain);
    }
    if domain.len() > MAX_DOMAIN_LEN {
        return Err(OperatorInfoError::DomainTooLong { len: domain.len() });
    }
    for label in domain.split('.') {
        if label.is_empty() {
            return Err(OperatorInfoError::InvalidDomainLabelEmpty);
        }
        if label.len() > MAX_LABEL_OR_ROLE_LEN {
            return Err(OperatorInfoError::InvalidDomainLabelTooLong {
                label: label.to_string(),
                len: label.len(),
            });
        }
        for c in label.chars() {
            if !is_valid_char(c) {
                return Err(OperatorInfoError::InvalidDomainCharacter { char: c });
            }
        }
        if label.starts_with('-') || label.ends_with('-') {
            return Err(OperatorInfoError::DomainLabelHyphenBoundary { label: label.to_string() });
        }
    }
    Ok(())
}

fn validate_role(role: &str) -> Result<(), OperatorInfoError> {
    if role.is_empty() {
        return Err(OperatorInfoError::EmptyRole);
    }
    if role.len() > MAX_LABEL_OR_ROLE_LEN {
        return Err(OperatorInfoError::RoleTooLong { len: role.len() });
    }

    for c in role.chars() {
        if !is_valid_char(c) {
            return Err(OperatorInfoError::InvalidRoleCharacter { char: c });
        }
    }
    if role.starts_with('-') || role.ends_with('-') {
        return Err(OperatorInfoError::RoleHyphenBoundary(role.to_string()));
    }
    Ok(())
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OperatorInfo {
    domain: String,
    role: String,
}

impl OperatorInfo {
    pub fn new(
        domain: impl Into<String>,
        role: impl Into<String>,
    ) -> Result<Self, OperatorInfoError> {
        let domain = domain.into();
        let role = role.into();
        validate_domain(&domain)?;
        validate_role(&role)?;
        Ok(Self { domain, role })
    }

    pub fn domain(&self) -> &str {
        &self.domain
    }

    pub fn role(&self) -> &str {
        &self.role
    }
}

impl TryFrom<&avs_proto_rust::avs::OperatorInfo> for OperatorInfo {
    type Error = OperatorInfoError;

    fn try_from(proto: &avs_proto_rust::avs::OperatorInfo) -> Result<Self, Self::Error> {
        Self::new(&proto.operator_domain, &proto.operator_role)
    }
}

impl TryFrom<avs_proto_rust::avs::OperatorInfo> for OperatorInfo {
    type Error = OperatorInfoError;

    fn try_from(proto: avs_proto_rust::avs::OperatorInfo) -> Result<Self, Self::Error> {
        Self::new(proto.operator_domain, proto.operator_role)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_reject_empty_domain() {
        let err = OperatorInfo::new("", "role").unwrap_err();
        assert_eq!(err, OperatorInfoError::EmptyDomain);
    }

    #[test]
    fn test_reject_empty_role() {
        let err = OperatorInfo::new("google.com", "").unwrap_err();
        assert_eq!(err, OperatorInfoError::EmptyRole);
    }

    #[test]
    fn test_valid_operator_info_multi_segment() {
        let op = OperatorInfo::new("corp.google.com", "encrypted-zone").unwrap();
        assert_eq!(op.domain(), "corp.google.com");
        assert_eq!(op.role(), "encrypted-zone");
    }

    #[test]
    fn test_valid_operator_info_single_segment_domain() {
        let op = OperatorInfo::new("google", "prober").unwrap();
        assert_eq!(op.domain(), "google");
        assert_eq!(op.role(), "prober");
    }

    #[test]
    fn test_valid_operator_info_underscores_and_hyphens() {
        let op = OperatorInfo::new("my_cluster_01.sub-domain.org", "worker_node-1").unwrap();
        assert_eq!(op.domain(), "my_cluster_01.sub-domain.org");
        assert_eq!(op.role(), "worker_node-1");
    }

    #[test]
    fn test_valid_operator_info_max_lengths() {
        // 63-char label
        let label_63 = "a".repeat(63);
        let role_63 = "b".repeat(63);
        let domain_63 = label_63.clone();
        let op = OperatorInfo::new(&domain_63, &role_63).unwrap();
        assert_eq!(op.domain(), domain_63);
        assert_eq!(op.role(), role_63);

        // 253-char domain: 3 x 63-char labels + 1 x 61-char label + 3 dots =
        // 63+63+63+61+3 = 253
        let label_61 = "c".repeat(61);
        let domain_253 = format!("{}.{}.{}.{}", label_63, label_63, label_63, label_61);
        assert_eq!(domain_253.len(), 253);
        let op253 = OperatorInfo::new(&domain_253, "role").unwrap();
        assert_eq!(op253.domain(), domain_253);
    }

    #[test]
    fn test_reject_domain_too_long() {
        // 254-char domain
        let label_63 = "a".repeat(63);
        let label_62 = "c".repeat(62);
        let domain_254 = format!("{}.{}.{}.{}", label_63, label_63, label_63, label_62);
        assert_eq!(domain_254.len(), 254);
        let err = OperatorInfo::new(&domain_254, "role").unwrap_err();
        assert_eq!(err, OperatorInfoError::DomainTooLong { len: 254 });
    }

    #[test]
    fn test_reject_domain_label_too_long() {
        let label_64 = "a".repeat(64);
        let err = OperatorInfo::new(&label_64, "role").unwrap_err();
        assert_eq!(err, OperatorInfoError::InvalidDomainLabelTooLong { label: label_64, len: 64 });
    }

    #[test]
    fn test_reject_role_too_long() {
        let role_64 = "r".repeat(64);
        let err = OperatorInfo::new("google.com", &role_64).unwrap_err();
        assert_eq!(err, OperatorInfoError::RoleTooLong { len: 64 });
    }

    #[test]
    fn test_reject_domain_consecutive_dots() {
        let err = OperatorInfo::new("google..com", "role").unwrap_err();
        assert_eq!(err, OperatorInfoError::InvalidDomainLabelEmpty);
    }

    #[test]
    fn test_reject_domain_leading_dot() {
        let err = OperatorInfo::new(".google.com", "role").unwrap_err();
        assert_eq!(err, OperatorInfoError::InvalidDomainLabelEmpty);
    }

    #[test]
    fn test_reject_domain_trailing_dot() {
        let err = OperatorInfo::new("google.com.", "role").unwrap_err();
        assert_eq!(err, OperatorInfoError::InvalidDomainLabelEmpty);
    }

    #[test]
    fn test_reject_domain_with_slashes() {
        let err = OperatorInfo::new("google.com/evil", "role").unwrap_err();
        assert_eq!(err, OperatorInfoError::InvalidDomainCharacter { char: '/' });
    }

    #[test]
    fn test_reject_invalid_characters() {
        let invalid_chars = [
            ':', ' ', ',', '"', '\'', '\\', '@', '#', '$', '%', '^', '&', '*', '(', ')', '+', '=',
            '[', ']', '{', '}', '|', '<', '>', '?', '!', '\0', '\n', '\u{00E9}',
        ];
        for c in invalid_chars {
            let domain = format!("google{}com", c);
            let err_domain = OperatorInfo::new(&domain, "role").unwrap_err();
            assert_eq!(
                err_domain,
                OperatorInfoError::InvalidDomainCharacter { char: c },
                "Failed for domain char {:?}",
                c
            );

            let role = format!("role{}admin", c);
            let err_role = OperatorInfo::new("google.com", &role).unwrap_err();
            assert_eq!(
                err_role,
                OperatorInfoError::InvalidRoleCharacter { char: c },
                "Failed for role char {:?}",
                c
            );
        }

        for c in ['.', '/'] {
            let role = format!("role{}admin", c);
            let err_role = OperatorInfo::new("google.com", &role).unwrap_err();
            assert_eq!(err_role, OperatorInfoError::InvalidRoleCharacter { char: c });
        }
    }

    #[test]
    fn test_reject_hyphen_boundaries() {
        let err = OperatorInfo::new("-google.com", "role").unwrap_err();
        assert_eq!(
            err,
            OperatorInfoError::DomainLabelHyphenBoundary { label: "-google".to_string() }
        );

        let err = OperatorInfo::new("google-.com", "role").unwrap_err();
        assert_eq!(
            err,
            OperatorInfoError::DomainLabelHyphenBoundary { label: "google-".to_string() }
        );

        let err = OperatorInfo::new("corp.-sub-.com", "role").unwrap_err();
        assert_eq!(
            err,
            OperatorInfoError::DomainLabelHyphenBoundary { label: "-sub-".to_string() }
        );

        let err = OperatorInfo::new("google.com", "-role").unwrap_err();
        assert_eq!(err, OperatorInfoError::RoleHyphenBoundary("-role".to_string()));

        let err = OperatorInfo::new("google.com", "role-").unwrap_err();
        assert_eq!(err, OperatorInfoError::RoleHyphenBoundary("role-".to_string()));

        let err = OperatorInfo::new("google.com", "-").unwrap_err();
        assert_eq!(err, OperatorInfoError::RoleHyphenBoundary("-".to_string()));
    }

    #[test]
    fn test_proto_try_from_conversions() {
        let proto = avs_proto_rust::avs::OperatorInfo {
            operator_domain: "google.com".to_string(),
            operator_role: "encrypted-zone".to_string(),
        };

        // Borrowed conversion
        let op_ref = OperatorInfo::try_from(&proto).unwrap();
        assert_eq!(op_ref.domain(), "google.com");
        assert_eq!(op_ref.role(), "encrypted-zone");

        // Owned conversion
        let op_owned = OperatorInfo::try_from(proto).unwrap();
        assert_eq!(op_owned.domain(), "google.com");
        assert_eq!(op_owned.role(), "encrypted-zone");

        // Invalid proto
        let bad_proto = avs_proto_rust::avs::OperatorInfo {
            operator_domain: "".to_string(),
            operator_role: "none".to_string(),
        };
        assert_eq!(OperatorInfo::try_from(&bad_proto), Err(OperatorInfoError::EmptyDomain));
    }

    #[test]
    fn test_tonic_status_conversion() {
        let err = OperatorInfoError::EmptyDomain;
        let status: tonic::Status = err.into();
        assert_eq!(status.code(), tonic::Code::InvalidArgument);
        assert!(status.message().contains("operator_domain must not be empty"));
    }
}
