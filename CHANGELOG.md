# Changelog

All notable changes to this project will be documented in this file. See [commit-and-tag-version](https://github.com/absolute-version/commit-and-tag-version) for commit guidelines.

## 1.0.0 (2026-09-24)


### ⚠ BREAKING CHANGES

* Remove Private Aratea policy

### Features

* Remove Private Aratea policy

## 0.16.0 (2026-09-15)


### Dependencies

* **deps:** Update policies (diff hash: 5fc3e54d)
* **deps:** update the EZ policy from head

## 0.15.0 (2026-09-08)


### Dependencies

* **deps:** update binary checksums and policies
* **deps:** Update Oak dependency
* **deps:** update Oak pin to 973bf96c
* **deps:** Update policies (diff hash: 6d564ea1)
* **deps:** Update policies (diff hash: f9243808)


### Features

* compile C2SP tlog verification into the staging enclave
* replace toolchains_llvm with toolchains_llvm_bootstrapped

## 0.14.0 (2026-08-27)


### Dependencies

* **deps:** Update policies (diff hash: 310ae365)


### Bug Fixes

* mark SAN extension as critical in generated certificates

## 0.13.0 (2026-08-24)


### Dependencies

* **deps:** Update Oak dependency
* **deps:** Update tlog policies (diff hash: c074fde8)


### Features

* accept C2SP proofs in the tlog policies
* set certificate validity based on endorsments validity


### Bug Fixes

* keep refreshed tlog policies non-executable

## 0.12.0 (2026-08-18)


### Features

* add a feature flag for tlog verification
* Add Encrypted Zone staging policy
* auto-register policies by name from build rules
* embed a per-environment tlog policy
* introduce policy name field in Policy proto and textprotos
* support certification parameters in requests

## 0.11.0 (2026-08-07)


### Dependencies

* **deps:** Update DevKit to release-3.11.0
* **deps:** Update policies (diff hash: 5c224d3b)


### Features

* add c2sp policy behind flag
* validate operator domain and role against policy rules


### Bug Fixes

* Fix heap memory leaking to self-signed cert
* Validate operator_info. Build SAN extension safely

## 0.10.0 (2026-07-27)


### Dependencies

* **deps:** Update PES root certificates (diff hash: 66bc794d)

## 0.9.0 (2026-07-22)


### Features

* AVS sets the Authority Key Identifier extension in issued certs

## 0.8.0 (2026-07-21)


### Dependencies

* **deps:** Update PES root certificates (diff hash: 81d420b5)
* **deps:** Update PES root certificates (diff hash: 97bb3431)


### Features

* bump up oak dependency version
* enable policy enforcement
* migrate policies to binary_mpms ref values
* populate PES keys in runtime_agent
* skip binary_mpms for dev policy
* update AVS prober policy
* update Oak dpendency
* update Oak for updated package verification

## 0.7.0 (2026-07-13)


### Features

* add `all` tlog policy for each policy
* correct Issuer DN in certificates

## 0.6.0 (2026-07-07)


### Features

* add DEVELOPMENT_CB_CERTIFICATE support
* add mTLS and TLS development policy hints
* integrate devkit/check_checksums --update

## 0.5.0 (2026-07-02)


### Dependencies

* **deps:** Update DevKit to release-3.10.0


### Features

* Pass public keys from PES certs to policies
* update issuer name in leaf cert
* update prober workload names in attestation policy

## 0.4.0 (2026-06-29)


### Features

* Define correct default values for application config
* update comments and tests for policies

## 0.3.0 (2026-06-25)


### Features

* Add a function which loads certificates from glob
* add constraints on provisioned cert
* add policy fetcher based on policy hint
* add policy proto and mapping to AVS repo
* Bundle PES cert into OCI image
* introduce EZ and Private Aratea policies
* introduce prober policy
* load reference values to certify workloads
* update reference values for all policies


### Bug Fixes

* Store PES prod certs under prod/ directory in tar

## 0.2.0 (2026-06-18)


### Dependencies

* **deps:** Update DevKit to release-3.9.0


### Features

* add AVS support for issuing DNS role names
* add different key extended use cases
* add operator role in provisioned role


### Bug Fixes

* Preserve specific TCA error codes in AVS server


### Documentation

* Longer description for the purpose of AVS

## 0.1.0 (2026-06-12)


### Features

* Initial release
