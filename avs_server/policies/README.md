# AVS Policies

This directory contains hardcoded attestation policies for each role that AVS
can provision certificates for. Each subdirectory holds a `policy.textproto`
file representing an
[`attestation_verification.Policy`](../proto/policy.proto) message.

At build time, each `policy.textproto` is converted to a `policy.binarypb`
via a Bazel `genrule` using `protoc --encode`. The `policy.binarypb` is then
embedded in the `attestation_verification.AttestationVerificationService`
server binary.

## Policies

| Directory                | PolicyHint(s)                                                  |
| ------------------------ | -------------------------------------------------------------- |
| `private_aratea_server/` | `PRIVATE_ARATEA_FRONTEND_CB_CERTIFICATE`                       |
| `encrypted_zone/`        | `EZ_ENFORCER_CB_CERTIFICATE`, `EZ_TSM_CB_FRONTEND_CERTIFICATE` |
| `prober/`                | `PROBER_CB_CERTIFICATE`                                        |
