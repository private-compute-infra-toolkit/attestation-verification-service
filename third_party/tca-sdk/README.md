# TCA SDK Libraries

This repository contains the Trusted Certificate Authority (TCA) SDK, designed to facilitate integration with TCA. The SDK provides a language-specific gRPC wrapper to properly form requests and execute RPC calls.

As of now, **Oak** is the only supported platform. **Rust** is the only supported language.

## Usage

See `example/rust/oak/issue_certificate.rs` for a complete, runnable example of how to initialize the client, generate a CSR, and request a certificate.

### Configuration & Proxies

The `OakTcaClient` uses standard gRPC (via `tonic`).

- **Proxies**: If connecting via a proxy on the host (e.g., for internet access from a QEMU guest), simply pass the proxy's URL as the endpoint.
  - Example: `OakTcaClient::create("http://10.0.2.2:8080")`
- **TLS**: Use `https://` for TLS-terminated endpoints and `http://` for plaintext (local) connections.

## Repo Structure

The SDK is architected to support multiple platforms by separating platform-agnostic core logic and traits from platform-specific implementations:

1.  **`tca_common` (`rust/common`)**:

    This crate contains platform-agnostic core logic, traits, and types. It provides the building blocks shared across all platform implementations.

    - **Types**: `Csr`, `Certificate`, and `CertificateChain`.
    - **Traits**: `AttestationProvider` (for fetching evidence) and `TcaTransport` (for network communication).
    - **Core Logic**: `StandardTcaClient`, a generic implementation of `TcaClient` that coordinates the attestation and transport layers.

2.  **`tca_oak` (`rust/oak`)**:

    This crate contains the platform-specific implementation for Oak Containers.

    - **OakAttestationProvider**: Implements the `AttestationProvider` trait to fetch evidence from the Oak Orchestrator.
    - **OakTcaClient**: A convenience wrapper that pre-wires the `OakAttestationProvider` and the default gRPC transport (`TonicTcaTransport`), implementing `TcaClient`.

## WARNING: Unstable

**The SDK is currently experimental and unstable. Backward compatibility is not guaranteed.**
