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

| Directory         | PolicyHint(s)                                                                         |
| ----------------- | ------------------------------------------------------------------------------------- |
| `pa-014c68966d/`  | `pa-014c68966d`, `pa-014c68966d-nonprod`                                              |
| `pa-2481dfc23b/`  | `pa-2481dfc23b`, `pa-2481dfc23b-nonprod`                                              |
| `pa-45468cbcc9/`  | `pa-45468cbcc9`, `pa-45468cbcc9-nonprod`                                              |
| `pa-bfee2c4a65/`  | `pa-bfee2c4a65`, `pa-bfee2c4a65-nonprod`                                              |
| `pa-eba5b05bf8/`  | `pa-eba5b05bf8`, `pa-eba5b05bf8-nonprod`                                              |
| `encrypted_zone/` | `EZ_ENFORCER_CB_CERTIFICATE`, `EZ_TSM_CB_FRONTEND_CERTIFICATE`, `pa-frontend-nonprod` |
| `prober/`         | `PROBER_CB_CERTIFICATE`                                                               |
| `prober_ez/`      | `EZ_ENFORCER_CB_CERTIFICATE`                                                          |
