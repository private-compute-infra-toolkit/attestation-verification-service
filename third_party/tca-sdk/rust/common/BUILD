# Copyright 2026 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

load("@rules_rust//rust:defs.bzl", "rust_library", "rust_test")
load("@rules_rust_prost//:defs.bzl", "rust_prost_library")

package(default_visibility = ["//visibility:public"])

rust_prost_library(
    name = "trusted_certificate_authority_rust_proto",
    proto = "@pcit_api//google/tca/v1:trusted_certificate_authority_proto",
)

rust_library(
    name = "tca_common",
    srcs = glob(["src/**/*.rs"]),
    proc_macro_deps = [
        "@crates//:async-trait",
    ],
    deps = [
        ":trusted_certificate_authority_rust_proto",
        "@crates//:thiserror",
        "@crates//:tonic",
        "@crates//:x509-cert",
    ],
)

rust_test(
    name = "tca_common_test",
    size = "small",
    crate = ":tca_common",
    deps = [
        "@crates//:rand",
        "@crates//:rsa",
        "@crates//:tokio",
        "@crates//:x509-cert",
    ],
)
