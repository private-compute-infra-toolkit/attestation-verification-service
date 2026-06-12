// Copyright 2026 Google LLC.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

use std::env;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let protobuf_include_path =
        &env::var("DESCRIPTOR_PROTO_PATH").unwrap().replace("google/protobuf/descriptor.proto", "");

    let oak_include_path =
        &env::var("OAK_PROTO_INCLUDE")?.replace("proto/attestation/evidence.proto", "");
    tonic_prost_build::configure()
        .build_client(true)
        .build_server(true)
        .type_attribute(
            "attestation_verification.CertifyAttestationStreamRequest.request",
            "#[allow(clippy::large_enum_variant)]",
        )
        .type_attribute(
            "attestation_verification.CertifyAttestationStreamRequest.Request",
            "#[allow(clippy::large_enum_variant)]",
        )
        .type_attribute(
            "attestation_verification.CertifyAttestationStreamResponse.request",
            "#[allow(clippy::large_enum_variant)]",
        )
        .type_attribute(
            "attestation_verification.CertifyAttestationStreamResponse.Request",
            "#[allow(clippy::large_enum_variant)]",
        )
        .extern_path(".oak.attestation.v1", "::oak_proto_rust::oak::attestation::v1")
        .compile_protos(
            &["../proto/attestation_verification.proto"],
            &["../", "../../", protobuf_include_path, oak_include_path],
        )?;

    Ok(())
}
