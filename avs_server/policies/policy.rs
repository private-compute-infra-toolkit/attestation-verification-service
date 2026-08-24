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

use std::collections::HashMap;
use std::sync::OnceLock;

use avs_proto_rust::avs::{Policy, PolicyBundle};
use prost::Message;

pub mod c2sp;
mod certs;
pub mod pes;

// Embedded policy bundle generated at build time.
const POLICY_BUNDLE: &[u8] = include_bytes!("policy_bundle.binarypb");

/// Decodes a `PolicyBundle` binarypb and builds a map of policy name to Policy.
///
/// Used by both prod and google_internal policy modules to avoid code
/// duplication.
pub fn build_policy_registry(bundle_bytes: &[u8]) -> HashMap<String, Policy> {
    let bundle = PolicyBundle::decode(bundle_bytes).expect("failed to decode policy bundle");
    bundle
        .policies
        .into_iter()
        .filter(|p| !p.name.is_empty())
        .map(|p| (p.name.clone(), p))
        .collect()
}

/// Returns the lazily-initialized policy registry.
fn policy_registry() -> &'static HashMap<String, Policy> {
    static REGISTRY: OnceLock<HashMap<String, Policy>> = OnceLock::new();
    REGISTRY.get_or_init(|| build_policy_registry(POLICY_BUNDLE))
}

/// Configuration options for looking up and validating policies.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct PoliciesConfig {
    pub include_development_policy: bool,
    /// Enables verification of C2SP transparency log inclusion proofs.
    pub enable_c2sp_tlog: bool,
}

/// Returns the `Policy` associated with the given policy name.
pub fn get_policy(name: &str) -> anyhow::Result<Policy> {
    get_policy_with_config(name, &PoliciesConfig::default())
}

/// Returns the `Policy` associated with the given policy name and
/// configuration options.
pub fn get_policy_with_config(name: &str, config: &PoliciesConfig) -> anyhow::Result<Policy> {
    get_policy_with_config_and_c2sp_policy(name, config, c2sp::PROD_VERIFIER_POLICY)
}

/// Returns the `Policy` associated with the given policy name and
/// configuration options, injecting `c2sp_policy` into every C2SP tlog
/// reference value it contains.
#[cfg_attr(not(feature = "enable_tessera"), allow(unused_variables))]
pub fn get_policy_with_config_and_c2sp_policy(
    name: &str,
    config: &PoliciesConfig,
    c2sp_policy: &str,
) -> anyhow::Result<Policy> {
    if name == "development" && !config.include_development_policy {
        anyhow::bail!("policy not supported: {}", name);
    }

    let mut policy = policy_registry()
        .get(name)
        .cloned()
        .ok_or_else(|| anyhow::anyhow!("unrecognized policy name: {}", name))?;

    pes::inject_pes_keys(&mut policy)?;
    #[cfg(feature = "enable_tessera")]
    if config.enable_c2sp_tlog {
        c2sp::inject_c2sp_policy(&mut policy, c2sp_policy)?;
    }

    Ok(policy)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn get_policy_private_aratea_returns_valid_policy() {
        let policy = get_policy("private_aratea_server").expect("failed to get policy");
        assert_eq!(policy.name, "private_aratea_server");
        assert_eq!(policy.workload_name, "private-aratea-server");
        let op = policy.operator_policy.expect("missing operator_policy");
        assert_eq!(op.rules.len(), 1);
        assert_eq!(op.rules[0].domain, "prod.google.com");
        assert_eq!(op.rules[0].role, "pa-frontend");
        assert!(policy.oak_reference_values.is_some());
    }

    #[test]
    fn get_policy_encrypted_zone_returns_valid_policy() {
        let policy = get_policy("encrypted_zone").expect("failed to get policy");
        assert_eq!(policy.name, "encrypted_zone");
        assert_eq!(policy.workload_name, "encrypted-zone");
        let op = policy.operator_policy.expect("missing operator_policy");
        assert_eq!(op.rules.len(), 1);
        assert_eq!(op.rules[0].domain, "prod.google.com");
        assert_eq!(op.rules[0].role, "pa-frontend");
        assert!(policy.oak_reference_values.is_some());
    }

    #[test]
    fn get_policy_prober_returns_valid_policy() {
        let policy = get_policy("prober").expect("failed to get policy");
        assert_eq!(policy.name, "prober");
        assert_eq!(policy.workload_name, "attestation-verification-service-prober");
        let op = policy.operator_policy.expect("missing operator_policy");
        assert_eq!(op.rules.len(), 1);
        assert_eq!(op.rules[0].domain, "prod.google.com");
        assert_eq!(op.rules[0].role, "prober");
        assert!(policy.oak_reference_values.is_some());
    }

    #[test]
    fn get_policy_development_returns_error() {
        let result = get_policy_with_config(
            "development",
            &PoliciesConfig { include_development_policy: false, ..Default::default() },
        );
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().to_string(), "policy not supported: development");
    }

    #[test]
    fn get_policy_development_enabled_returns_valid_policy() {
        let policy = get_policy_with_config(
            "development",
            &PoliciesConfig { include_development_policy: true, ..Default::default() },
        )
        .expect("failed to get policy");
        assert_eq!(policy.name, "development");
        assert_eq!(policy.workload_name, "unendorsed-development");
        let op = policy.operator_policy.expect("missing operator_policy");
        assert_eq!(op.rules.len(), 1);
        assert_eq!(op.rules[0].domain, "prod.google.com");
        assert_eq!(op.rules[0].role, "dev");
        assert!(policy.oak_reference_values.is_some());
    }

    #[test]
    fn get_policy_unrecognized_returns_error() {
        let result = get_policy("nonexistent_policy");
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().to_string(), "unrecognized policy name: nonexistent_policy");
    }
}
