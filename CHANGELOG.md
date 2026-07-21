# Changelog

All notable changes to this project will be documented in this file. See [commit-and-tag-version](https://github.com/absolute-version/commit-and-tag-version) for commit guidelines.

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
