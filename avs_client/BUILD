# Copyright 2026 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

load("@rules_rust//rust:defs.bzl", "rust_library", "rust_test")

package(default_visibility = ["//visibility:public"])

rust_library(
    name = "avs_client",
    srcs = [
        "src/attestation.rs",
        "src/client.rs",
        "src/lib.rs",
        "src/transport.rs",
    ],
    proc_macro_deps = [
        "@oak_crates_index//:async-trait",
    ],
    deps = [
        "//proto_rust:avs_client_proto_rust",
        "@oak//oak_proto_rust",
        "@oak//oak_sdk/containers:oak_sdk_containers",
        "@oak_crates_index//:anyhow",
        "@oak_crates_index//:coset",
        "@oak_crates_index//:tokio",
        "@oak_crates_index//:tokio-stream",
        "@oak_crates_index//:tonic",
        "@tca-sdk//rust/common:tca_common",
    ],
)

alias(
    name = "avs_oak",
    actual = ":avs_client",
)

rust_test(
    name = "avs_client_test",
    size = "small",
    crate = ":avs_client",
    deps = [
        "@oak//oak_attestation_verification",
        "@oak_crates_index//:p256",
        "@oak_crates_index//:rcgen",
    ],
)
