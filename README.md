# Attestation Verification Service (AVS)

[![Pre-Commit Scorecard](https://github.com/private-compute-infra-toolkit/attestation-verification-service/actions/workflows/pre-commit.yaml/badge.svg)](https://github.com/private-compute-infra-toolkit/attestation-verification-service/actions/workflows/pre-commit.yaml)
[![Build Scorecard](https://github.com/private-compute-infra-toolkit/attestation-verification-service/actions/workflows/build.yaml/badge.svg)](https://github.com/private-compute-infra-toolkit/attestation-verification-service/actions/workflows/build.yaml)
[![Test Scorecard](https://github.com/private-compute-infra-toolkit/attestation-verification-service/actions/workflows/test.yaml/badge.svg)](https://github.com/private-compute-infra-toolkit/attestation-verification-service/actions/workflows/test.yaml)
[![Coverage Scorecard](https://github.com/private-compute-infra-toolkit/attestation-verification-service/actions/workflows/coverage.yaml/badge.svg)](https://github.com/private-compute-infra-toolkit/attestation-verification-service/actions/workflows/coverage.yaml)

The Attestation Verification Service aims to verify measurements of running
workloads against a policy that is transparent and auditable.

## Getting started

To develop in the AVS repository, go through the following list of steps.

### Clone repo

```bash
git clone https://github.com/private-compute-infra-toolkit/attestation-verification-service
cd attestation-verification-service
```

### Prerequisites

DevKit relies on Docker to provide a hermetic environment. Ensure that [Docker](https://docs.docker.com/get-docker/) is installed and running on your system.

## Day-to-day workflows and actions

### Add or remove binaries

Only a few binaries are considered deliverables of the AVS repo. These are
distinguished in two locations:

1.  `./BUILD`: These binaries need to be wired up to `//:build_copy`
    which will make them show up in directory `artifacts/` for further
    processing (e.g. import via TR tool).
2.  `./checksums.txt`: Since we require all these binaries to build
    reproducibly, need to mention the latest binary path and digest in
    that file. This will enforce checking the reproducibility on
    presubmit and postsubmit.

### Update checksums

Since builds of the deliverable binaries are reproducible, we keep track of
their binary digests. The `checksums.txt` file contains the current SHA256
hashes of the binaries. This must be run after altering any of the deliverable
binaries. Don't execute the script at `scripts/update_checksums.sh` directly;
instead, invoke it using the following command:

```bash
devkit/build bazel run //:update_checksums
```

### Running Verification and Checks

This project uses DevKit to provide a hermetic, reproducible environment and ensure consistency across all developer setups. The sections below outline how to perform essential project verifications.

#### Gitlint

To run standalone GitLint validation for commit messages:

```bash
devkit/gitlint
```

#### Pre-commit

To perform formatting checks, linting, and full pre-commit validation:

```bash
devkit/pre-commit
```

#### Build

To compile all targets:

```bash
devkit/build bazel build //...
```

#### Test

To run tests:

```bash
devkit/build bazel test --config=run_all_tests //...
```

#### Coverage

To run test coverage analysis:

```bash
devkit/coverage
```

#### Native Execution

While DevKit is the recommended path, if you have Bazel installed natively on your host machine, commands like `build` and `test` can be executed natively without the wrapper:

```bash
bazel build //...
bazel test --config=run_all_tests //...
```
