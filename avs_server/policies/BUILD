# Copyright 2026 Google LLC
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

load("@rules_rust//rust:defs.bzl", "rust_library")

package(
    default_visibility = ["//visibility:public"],
)

rust_library(
    name = "policies",
    srcs = ["policy.rs"],
    compile_data = [
        "//avs_server/policies/private_aratea_server:policy_binarypb",
        "//avs_server/policies/encrypted_zone:policy_binarypb",
        "//avs_server/policies/prober:policy_binarypb",
    ],
    deps = [
        "//avs_server/proto_rust:avs_proto_rust",
        "@oak_crates_index//:anyhow",
        "@oak_crates_index//:prost",
    ],
)
