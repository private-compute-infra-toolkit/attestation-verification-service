#
# Copyright 2025 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     https://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#

load("@oak//bazel:defs.bzl", "oci_runtime_bundle")
load("@rules_oci//oci:defs.bzl", "oci_image")
load("@rules_rust//rust:defs.bzl", "rust_binary", "rust_library", "rust_test")
load("@tar.bzl", "mutate", "tar")

package(
    default_visibility = ["//visibility:public"],
)

AVS_SERVER_LIB_SRCS = [
    "src/ca.rs",
    "src/config.rs",
    "src/csr.rs",
    "src/lib.rs",
    "src/server.rs",
]

AVS_SERVER_LIB_DEPS = [
    "//avs_server/proto_rust:avs_proto_rust",
    "@boringssl//rust/bssl-sys",
    "@crates//:glob",
    "@oak//oak_attestation_verification",
    "@oak//oak_attestation_verification_types",
    "@oak//oak_proto_rust",
    "@oak//oak_time",
    "@oak//oak_time:oak_time_std",
    "@oak_crates_index//:anyhow",
    "@oak_crates_index//:log",
    "@oak_crates_index//:serde",
    "@oak_crates_index//:serde_json",
    "@oak_crates_index//:tokio",
    "@oak_crates_index//:tokio-stream",
    "@oak_crates_index//:tonic",
    "@tca-sdk//rust/common:tca_common",
]

AVS_SERVER_DEPS = [
    "//avs_server/proto_rust:avs_proto_rust",
    "@oak//oak_sdk/containers:oak_sdk_containers",
    "@oak_crates_index//:anyhow",
    "@oak_crates_index//:env_logger",
    "@oak_crates_index//:log",
    "@oak_crates_index//:serde",
    "@oak_crates_index//:serde_json",
    "@oak_crates_index//:tokio",
    "@oak_crates_index//:tonic",
    "@tca-sdk//rust/common:tca_common",
    "@tca-sdk//rust/oak:tca_oak",
]

rust_library(
    name = "avs_server_lib",
    srcs = AVS_SERVER_LIB_SRCS,
    compile_data = [
        "src/c2sp_policy.txt",
    ],
    deps = [
        "//avs_server/policies",
    ] + AVS_SERVER_LIB_DEPS,
)

rust_binary(
    name = "avs_server",
    srcs = [
        "src/main.rs",
    ],
    deps = [
        ":avs_server_lib",
    ] + AVS_SERVER_DEPS,
)

rust_test(
    name = "avs_server_lib_test",
    srcs = ["tests/avs_server_lib_test.rs"],
    compile_data = ["//avs_server/testdata:test_data"],
    proc_macro_deps = [
        "@oak_crates_index//:async-trait",
    ],
    deps = [
        ":avs_server_lib",
        "//avs_server/proto_rust:avs_proto_rust",
        "@crates//:rcgen",
        "@crates//:x509-cert",
        "@crates//:x509-verify",
        "@oak//oak_attestation_verification_types",
        "@oak//oak_proto_rust",
        "@oak_crates_index//:anyhow",
        "@oak_crates_index//:chrono",
        "@oak_crates_index//:ciborium",
        "@oak_crates_index//:coset",
        "@oak_crates_index//:hex",
        "@oak_crates_index//:log",
        "@oak_crates_index//:p256",
        "@oak_crates_index//:pem",
        "@oak_crates_index//:prost",
        "@oak_crates_index//:rand",
        "@oak_crates_index//:sha2",
        "@oak_crates_index//:tempfile",
        "@oak_crates_index//:tokio",
        "@oak_crates_index//:tokio-stream",
        "@oak_crates_index//:tonic",
        "@tca-sdk//rust/common:tca_common",
    ],
)

rust_test(
    name = "avs_server_lib_unit_test",
    crate = ":avs_server_lib",
)

rust_test(
    name = "c2sp_policy_test",
    srcs = ["tests/c2sp_policy_test.rs"],
    compile_data = ["src/c2sp_policy.txt"],
    deps = [
        "@oak//tr/c2sp",
    ],
)

tar(
    name = "avs_server_tar",
    srcs = [":avs_server"],
    mutate = mutate(strip_prefix = package_name()),
)

tar(
    name = "pes_certs_tar",
    srcs = ["//:pes_certs"],
    mutate = mutate(
        package_dir = "etc/pes-certs/prod",
        strip_prefix = "resources/pcit_root_certs/prod/pes-cert",
    ),
)

oci_image(
    name = "avs_server_image",
    base = "@distroless_cc",
    entrypoint = ["/avs_server"],
    tars = [
        ":avs_server_tar",
        ":pes_certs_tar",
    ],
)

oci_runtime_bundle(
    name = "avs_server_bundle",
    image = ":avs_server_image",
)
