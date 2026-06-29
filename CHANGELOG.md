# Changelog

All notable changes to this project will be documented in this file. See [commit-and-tag-version](https://github.com/absolute-version/commit-and-tag-version) for commit guidelines.

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
