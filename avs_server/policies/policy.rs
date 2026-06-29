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

use avs_proto_rust::avs::{Policy, PolicyHint};
use prost::Message;

// Embedded policy binaries generated from textproto files at build time.
const PRIVATE_ARATEA_SERVER_POLICY: &[u8] = include_bytes!("private_aratea_server/policy.binarypb");
const ENCRYPTED_ZONE_POLICY: &[u8] = include_bytes!("encrypted_zone/policy.binarypb");
const PROBER_POLICY: &[u8] = include_bytes!("prober/policy.binarypb");

/// Returns the `Policy` associated with the given `PolicyHint`.
pub fn get_policy(hint: PolicyHint) -> anyhow::Result<Policy> {
    let policy_bytes = match hint {
        PolicyHint::Unspecified => {
            anyhow::bail!("cannot fetch policy for POLICY_HINT_UNSPECIFIED")
        }
        PolicyHint::PrivateArateaFrontendCbCertificate => PRIVATE_ARATEA_SERVER_POLICY,
        PolicyHint::EzEnforcerCbCertificate | PolicyHint::EzTsmCbFrontendCertificate => {
            ENCRYPTED_ZONE_POLICY
        }
        PolicyHint::ProberCbCertificate => PROBER_POLICY,
    };
    Policy::decode(policy_bytes).map_err(|e| anyhow::anyhow!("failed to decode policy: {}", e))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn get_policy_unspecified_returns_error() {
        let result = get_policy(PolicyHint::Unspecified);
        assert!(result.is_err());
    }

    #[test]
    fn get_policy_private_aratea_returns_valid_policy() {
        let policy = get_policy(PolicyHint::PrivateArateaFrontendCbCertificate)
            .expect("failed to get policy");
        assert_eq!(policy.workload_name, "private-aratea-server");
        assert!(policy.oak_reference_values.is_some());
    }

    #[test]
    fn get_policy_ez_enforcer_returns_valid_policy() {
        let policy = get_policy(PolicyHint::EzEnforcerCbCertificate).expect("failed to get policy");
        assert_eq!(policy.workload_name, "encrypted-zone");
        assert!(policy.oak_reference_values.is_some());
    }

    #[test]
    fn get_policy_ez_tsm_frontend_returns_valid_policy() {
        let policy =
            get_policy(PolicyHint::EzTsmCbFrontendCertificate).expect("failed to get policy");
        assert_eq!(policy.workload_name, "encrypted-zone");
        assert!(policy.oak_reference_values.is_some());
    }

    #[test]
    fn get_policy_ez_enforcer_and_tsm_frontend_return_same_policy() {
        let enforcer =
            get_policy(PolicyHint::EzEnforcerCbCertificate).expect("failed to get policy");
        let frontend =
            get_policy(PolicyHint::EzTsmCbFrontendCertificate).expect("failed to get policy");
        assert_eq!(enforcer, frontend);
    }

    #[test]
    fn get_policy_prober_returns_valid_policy() {
        let policy = get_policy(PolicyHint::ProberCbCertificate).expect("failed to get policy");
        assert_eq!(policy.workload_name, "prober");
        assert!(policy.oak_reference_values.is_some());
    }
}
