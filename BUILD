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
load("@com_google_protobuf//bazel/toolchains:proto_toolchain.bzl", "proto_toolchain")
load("@rules_rust//rust:defs.bzl", "rust_library_group")
load("@rules_rust_prost//:defs.bzl", "rust_prost_toolchain")

package(
    default_visibility = ["//:internal"],
)

package_group(
    name = "internal",
    packages = [
        "//...",
    ],
)

# Implicitly creates `{name}_toolchain`.
proto_toolchain(
    name = "proto",
    proto_compiler = "@com_google_protobuf//:protoc",
)

rust_library_group(
    name = "prost_runtime",
    deps = [
        "@oak_crates_index//:prost",
    ],
)

rust_library_group(
    name = "tonic_runtime",
    deps = [
        ":prost_runtime",
        "@oak_crates_index//:tonic",
        "@oak_crates_index//:tonic-prost",
    ],
)

rust_prost_toolchain(
    name = "prost_toolchain_impl",
    prost_plugin = "@crates//:protoc-gen-prost__protoc-gen-prost",
    prost_runtime = ":prost_runtime",
    prost_types = "@oak_crates_index//:prost-types",
    tonic_plugin = "@crates//:protoc-gen-tonic__protoc-gen-tonic",
    tonic_runtime = ":tonic_runtime",
)

toolchain(
    name = "prost_toolchain",
    toolchain = "prost_toolchain_impl",
    toolchain_type = "@rules_rust_prost//:toolchain_type",
)

genrule(
    name = "build_copy",
    srcs = [
        "//avs_server",
        "//avs_server:avs_server_bundle",
    ],
    outs = ["copy_to_dist.bin"],
    cmd = """cat <<EOF > "$@"
cp -f $(execpath //avs_server:avs_server) artifacts/avs_enclave
cp -f $(execpath //avs_server:avs_server_bundle) artifacts/avs_enclave_bundle.tar
EOF""",
    executable = True,
    local = True,
    message = "Building and copying artifacts",
)

sh_binary(
    name = "update_checksums",
    srcs = ["scripts/update_checksums.sh"],
    data = [
        "//avs_server",
        "//avs_server:avs_server_bundle",
    ],
)
