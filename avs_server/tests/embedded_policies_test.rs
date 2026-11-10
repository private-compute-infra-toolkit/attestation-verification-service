//
// Copyright 2026 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//

use avs_server_lib::{
    csr::{create_verifier, Layer2Options},
    layer2_shadow::{self, compute_candidate_id, Layer2ShadowContext},
    policies::{get_policy_with_config, list_policy_names, PoliciesConfig},
};
use oak_proto_rust::oak::attestation::v1::reference_values;

#[test]
#[allow(deprecated)]
fn test_all_embedded_policies_f5_requirements() {
    let policy_names = list_policy_names();
    assert!(!policy_names.is_empty(), "Embedded policy registry must not be empty");

    let config = PoliciesConfig { include_development_policy: true, enable_c2sp_tlog: false };

    for name in &policy_names {
        // 1. Every embedded policy loads (get_policy_with_config) and
        //    create_verifier succeeds
        let policy = get_policy_with_config(name, &config)
            .unwrap_or_else(|e| panic!("failed to load policy '{}': {:?}", name, e));

        let oak_rv = policy
            .oak_reference_values
            .as_ref()
            .unwrap_or_else(|| panic!("policy '{}' is missing oak_reference_values", name));

        let operator_role = policy
            .operator_policy
            .as_ref()
            .and_then(|op| op.rules.first())
            .map(|r| r.role.as_str())
            .unwrap_or("test_role");

        let shadow_candidate = policy.shadow.as_ref().and_then(|s| s.layer2.as_ref());
        let verifier_res = create_verifier(
            oak_rv,
            None,
            Layer2Options {
                shadow_layer2: shadow_candidate,
                enforce_strict_layer2: policy.enforce_strict_layer2,
                policy_name: name,
                operator_role,
                shadow_context: Layer2ShadowContext::default(),
            },
        );
        assert!(
            verifier_res.is_ok(),
            "create_verifier failed for policy '{}': {:?}",
            name,
            verifier_res.err()
        );

        // 2. enforce_strict_layer2 == false for every policy
        assert!(
            !policy.enforce_strict_layer2,
            "policy '{}' has enforce_strict_layer2 = true, must default to false",
            name
        );

        // 3. Every non-"development" CBT policy has non-empty
        //    layer2.binary_mpms
        // and no deprecated layer2.binary_mpm
        if name != "development"
            && let Some(reference_values::Type::Cbt(cbt)) = &oak_rv.r#type
        {
            let layer2 = cbt
                .layer2
                .as_ref()
                .unwrap_or_else(|| panic!("CBT policy '{}' missing layer2", name));

            assert!(
                !layer2.binary_mpms.is_empty(),
                "policy '{}' layer2.binary_mpms must be non-empty",
                name
            );

            assert!(
                layer2.binary_mpm.is_none(),
                "policy '{}' must not use deprecated binary_mpm",
                name
            );
        }

        // 4. If shadow.layer2 is set it has >=1 slot and candidate_id is stable
        if let Some(shadow_l2) = policy.shadow.as_ref().and_then(|s| s.layer2.as_ref()) {
            let slots = layer2_shadow::get_slots(shadow_l2);
            assert!(
                !slots.is_empty(),
                "policy '{}' shadow.layer2 is present but has 0 slots",
                name
            );

            let id1 = compute_candidate_id(shadow_l2);
            let id2 = compute_candidate_id(shadow_l2);
            assert_eq!(id1, id2, "candidate_id must be stable for policy '{}'", name);
            assert_eq!(id1.len(), 8, "candidate_id must be 8 hex characters");
            assert!(id1.chars().all(|c| c.is_ascii_hexdigit()), "candidate_id must be hexadecimal");
        }
    }
}
