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

use oak_attestation_verification::TransparentLayer2Policy;
use oak_attestation_verification_types::policy::Policy;
use oak_proto_rust::oak::{
    attestation::v1::{CbLayer2TransparentReferenceValues, EventAttestationResults},
    Variant,
};
use oak_time::Instant;

use crate::layer2_shadow::{
    self, CandidatePolicy, Layer2ShadowContext, ShadowInputs, StrictOutcome,
};

/// Authoritative Layer 2 policy implementation for AVS.
///
/// Wraps Oak's `TransparentLayer2Policy` to enforce either permissive matching
/// (default) or strict 1-to-1 matching (when `enforce_strict_layer2` is true).
/// In shadow mode, it runs strict candidate evaluation without modifying the
/// authoritative outcome.
pub struct AvsLayer2Policy {
    enforced: TransparentLayer2Policy,
    enforce_strict: bool,
    current_ref: CbLayer2TransparentReferenceValues,
    candidate: Option<CandidatePolicy>,
    policy_name: String,
    operator_role: String,
    shadow: Layer2ShadowContext,
}

impl AvsLayer2Policy {
    pub fn new(
        layer2_reference_values: &CbLayer2TransparentReferenceValues,
        shadow_candidate: Option<&CbLayer2TransparentReferenceValues>,
        enforce_strict: bool,
        policy_name: String,
        operator_role: String,
        shadow: Layer2ShadowContext,
    ) -> Self {
        let enforced = TransparentLayer2Policy::new(layer2_reference_values);
        let candidate = shadow_candidate.map(CandidatePolicy::new);
        Self {
            enforced,
            enforce_strict,
            current_ref: layer2_reference_values.clone(),
            candidate,
            policy_name,
            operator_role,
            shadow,
        }
    }
}

impl Policy<[u8]> for AvsLayer2Policy {
    fn verify(
        &self,
        verification_time: Instant,
        evidence: &[u8],
        endorsement: &Variant,
    ) -> anyhow::Result<EventAttestationResults> {
        let result = if self.enforce_strict {
            self.enforced.verify_with_strict_ref_values(verification_time, evidence, endorsement)
        } else {
            self.enforced.verify(verification_time, evidence, endorsement)
        };

        // Shadow is enabled: check with shadowed policy using the strict
        // verifier
        if self.shadow.settings.enabled {
            let start = std::time::Instant::now();
            let inputs = ShadowInputs {
                current: &self.enforced,
                current_ref: &self.current_ref,
                candidate: self.candidate.as_ref(),
                policy_name: &self.policy_name,
                operator_role: &self.operator_role,
                enforced_ok: result.is_ok(),
                enforced_outcome: if self.enforce_strict {
                    Some(StrictOutcome::classify(&result))
                } else {
                    None
                },
            };
            let catch_result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                let mut report =
                    layer2_shadow::run_shadow(&inputs, verification_time, evidence, endorsement);
                report.shadow_latency_ms = start.elapsed().as_millis() as u64;
                self.shadow.record(&report, result.is_ok());
            }));
            if let Err(e) = catch_result {
                log::warn!("layer2_shadow panicked during shadow execution: {:?}", e);
            }
        }

        result
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::layer2_shadow::ShadowSettings;
    use oak_proto_rust::oak::attestation::v1::{
        mpm_reference_value::Type as MrvType, CbLayer2TransparentEvent, Event, MpmPackage,
        MpmReferenceValue, MpmVersionIds,
    };
    use prost::Message;

    const TEST_TIME: Instant = Instant::from_unix_millis(1_000_000);

    /// Encodes a protobuf message into an Oak Attestation `Event` proto
    /// wrapper.
    fn encode_event_proto<M: Message>(type_url: &str, msg: &M) -> Vec<u8> {
        let event = Event {
            tag: String::new(),
            event: Some(prost_types::Any {
                type_url: type_url.to_string(),
                value: msg.encode_to_vec(),
            }),
        };
        event.encode_to_vec()
    }

    /// Creates an `MpmReferenceValue` matching a single specified version
    /// string.
    fn versions_ref_value(version: &str) -> MpmReferenceValue {
        MpmReferenceValue {
            r#type: Some(MrvType::Versions(MpmVersionIds { versions: vec![version.to_string()] })),
        }
    }

    /// Helper to construct serialized Layer-2 evidence containing the given MPM
    /// package versions.
    fn layer2_evidence(versions: &[&str]) -> Vec<u8> {
        let event = CbLayer2TransparentEvent {
            packages: versions
                .iter()
                .map(|v| MpmPackage { mpm_version_id: (*v).to_string(), ..Default::default() })
                .collect(),
        };
        encode_event_proto(
            "type.googleapis.com/oak.attestation.v1.CbLayer2TransparentEvent",
            &event,
        )
    }

    /// Invariant: In permissive mode (enforce_strict=false), AvsLayer2Policy
    /// verification results match plain TransparentLayer2Policy::verify exactly
    /// (both Ok and Err), with shadow on or off, and with candidates that pass
    /// or fail.
    #[test]
    fn test_permissive_mode_matches_transparent_policy() {
        // Baseline reference values defining 2 package slots: pkg_a and pkg_b.
        let ref_values = CbLayer2TransparentReferenceValues {
            binary_mpms: vec![versions_ref_value("pkg_a/1.0"), versions_ref_value("pkg_b/2.0")],
            ..Default::default()
        };
        let plain_policy = TransparentLayer2Policy::new(&ref_values);

        // Candidate 1: matches the evidence (strict match will pass).
        let candidate_pass = CbLayer2TransparentReferenceValues {
            binary_mpms: vec![versions_ref_value("pkg_a/1.0"), versions_ref_value("pkg_b/2.0")],
            ..Default::default()
        };
        // Candidate 2: completely disjoint from evidence (strict match will
        // fail).
        let candidate_fail = CbLayer2TransparentReferenceValues {
            binary_mpms: vec![versions_ref_value("unrelated/1.0")],
            ..Default::default()
        };

        // Test cases covering combinations of package counts and matching
        // status:
        let test_cases = vec![
            // (evidence versions, description)
            (vec!["pkg_a/1.0", "pkg_b/2.0"], "2 matching packages"),
            (vec!["pkg_a/1.0"], "fewer packages than slots (permissive ok, strict fail)"),
            (vec!["pkg_unknown/1.0"], "unknown package (fails both)"),
            (vec![], "zero packages (permissive ok with 0 endorsements, strict fail)"),
            (vec!["pkg_a/1.0", "pkg_b/2.0", "pkg_c/3.0"], "more packages than slots"),
        ];

        // Evaluate across all combinations:
        // 1. Shadow enabled vs disabled.
        // 2. Candidate absent vs passing candidate vs failing candidate.
        // 3. Various evidence structures.
        for enabled in [true, false] {
            for candidate in [None, Some(&candidate_pass), Some(&candidate_fail)] {
                for (versions, desc) in &test_cases {
                    let evidence = layer2_evidence(
                        &versions.iter().map(|s| s.as_ref()).collect::<Vec<&str>>(),
                    );
                    let plain_res = plain_policy.verify(TEST_TIME, &evidence, &Variant::default());

                    let avs_layer2_policy = AvsLayer2Policy::new(
                        &ref_values,
                        candidate,
                        /* enforce_strict= */ false,
                        /* policy_name= */ "test_policy".to_string(),
                        /* operator_role= */ "test_role".to_string(),
                        Layer2ShadowContext { settings: ShadowSettings { enabled }, metrics: None },
                    );

                    let avs_res =
                        avs_layer2_policy.verify(TEST_TIME, &evidence, &Variant::default());

                    // Invariant check: AvsLayer2Policy must produce the
                    // identical verification result as
                    // plain TransparentLayer2Policy regardless
                    // of shadow settings or candidate outcome.
                    assert_eq!(
                        plain_res.is_ok(),
                        avs_res.is_ok(),
                        "Mismatch on case '{}' with enabled={}",
                        desc,
                        enabled
                    );
                }
            }
        }
    }

    /// Tests that enforce_strict_layer2 toggles between permissive and strict
    /// one-to-one matching across all verification scenarios.
    #[test]
    fn test_enforce_strict_layer2_mode() {
        // Define reference values with 2 slots: pkg1 and pkg2.
        let ref_values = CbLayer2TransparentReferenceValues {
            binary_mpms: vec![versions_ref_value("pkg1/1.0"), versions_ref_value("pkg2/1.0")],
            ..Default::default()
        };

        // Case 1: When enforce_strict is false, permissive mode allows
        // multiple packages matching slots (e.g., 3 packages matching 2 slots).
        let policy_permissive = AvsLayer2Policy::new(
            &ref_values,
            /* shadow_candidate= */ None,
            /* enforce_strict= */ false,
            /* policy_name= */ "test_policy".to_string(),
            /* operator_role= */ "test_role".to_string(),
            Layer2ShadowContext { settings: ShadowSettings { enabled: true }, metrics: None },
        );
        let evidence_3_pkgs = layer2_evidence(&["pkg1/1.0", "pkg2/1.0", "pkg1/1.0"]);
        let res_permissive =
            policy_permissive.verify(TEST_TIME, &evidence_3_pkgs, &Variant::default());
        assert!(res_permissive.is_ok(), "Permissive mode must pass");

        // Case 2: When enforce_strict is true, strict 1-to-1 mode rejects
        // package count mismatch (3 evidence packages vs 2 reference
        // value slots).
        let policy_strict = AvsLayer2Policy::new(
            &ref_values,
            /* shadow_candidate= */ None,
            /* enforce_strict= */ true,
            /* policy_name= */ "test_policy".to_string(),
            /* operator_role= */ "test_role".to_string(),
            Layer2ShadowContext { settings: ShadowSettings { enabled: true }, metrics: None },
        );
        let res_strict = policy_strict.verify(TEST_TIME, &evidence_3_pkgs, &Variant::default());
        assert!(res_strict.is_err(), "Strict mode must fail on count mismatch");

        // Case 3: When packages match slots in an exact 1-to-1 correspondence
        // (2 packages for 2 slots), both permissive and strict modes pass.
        let evidence_2_pkgs = layer2_evidence(&["pkg1/1.0", "pkg2/1.0"]);
        let res_permissive_pass =
            policy_permissive.verify(TEST_TIME, &evidence_2_pkgs, &Variant::default());
        assert!(res_permissive_pass.is_ok(), "Permissive mode must pass on matching packages");
        let res_strict_pass =
            policy_strict.verify(TEST_TIME, &evidence_2_pkgs, &Variant::default());
        assert!(res_strict_pass.is_ok(), "Strict mode must pass on exact 1-to-1 match");

        // Case 4: When there are fewer packages than slots (1 package vs 2
        // slots):
        // - Permissive mode allows missing slots (passes).
        // - Strict mode rejects package count mismatch (fails).
        let evidence_1_pkg = layer2_evidence(&["pkg1/1.0"]);
        let res_permissive_fewer =
            policy_permissive.verify(TEST_TIME, &evidence_1_pkg, &Variant::default());
        assert!(
            res_permissive_fewer.is_ok(),
            "Permissive mode must pass when fewer packages than slots"
        );
        let res_strict_fewer =
            policy_strict.verify(TEST_TIME, &evidence_1_pkg, &Variant::default());
        assert!(res_strict_fewer.is_err(), "Strict mode must fail when fewer packages than slots");

        // Case 5: When evidence has an unverified version mismatch (pkg1/9.9):
        // Both permissive and strict modes fail.
        let evidence_wrong_version = layer2_evidence(&["pkg1/9.9", "pkg2/1.0"]);
        let res_permissive_wrong_version =
            policy_permissive.verify(TEST_TIME, &evidence_wrong_version, &Variant::default());
        assert!(
            res_permissive_wrong_version.is_err(),
            "Permissive mode must fail on version mismatch"
        );
        let res_strict_wrong_version =
            policy_strict.verify(TEST_TIME, &evidence_wrong_version, &Variant::default());
        assert!(res_strict_wrong_version.is_err(), "Strict mode must fail on version mismatch");

        // Case 6: When evidence has an unknown package (pkg_unknown/1.0):
        // Both permissive and strict modes fail.
        let evidence_unknown_pkg = layer2_evidence(&["pkg_unknown/1.0", "pkg2/1.0"]);
        let res_permissive_unknown =
            policy_permissive.verify(TEST_TIME, &evidence_unknown_pkg, &Variant::default());
        assert!(res_permissive_unknown.is_err(), "Permissive mode must fail on unknown package");
        let res_strict_unknown =
            policy_strict.verify(TEST_TIME, &evidence_unknown_pkg, &Variant::default());
        assert!(res_strict_unknown.is_err(), "Strict mode must fail on unknown package");

        // Case 7: When count matches (2 == 2) but packages cannot be matched
        // 1-to-1 (2 packages of pkg1/1.0 attempting to satisfy 2
        // distinct slots pkg1 and pkg2):
        // - Permissive mode allows duplicate packages to match the same slot
        //   (passes).
        // - Strict mode rejects slot-sharing (fails with NoOneToOneMatch).
        let evidence_no_1to1 = layer2_evidence(&["pkg1/1.0", "pkg1/1.0"]);
        let res_permissive_no_1to1 =
            policy_permissive.verify(TEST_TIME, &evidence_no_1to1, &Variant::default());
        assert!(
            res_permissive_no_1to1.is_ok(),
            "Permissive mode must pass on duplicate slot-sharing packages"
        );
        let res_strict_no_1to1 =
            policy_strict.verify(TEST_TIME, &evidence_no_1to1, &Variant::default());
        assert!(res_strict_no_1to1.is_err(), "Strict mode must fail on no 1-to-1 match");
    }
}
