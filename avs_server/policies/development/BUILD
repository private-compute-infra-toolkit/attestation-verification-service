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

package(
    default_visibility = ["//visibility:public"],
)

genrule(
    name = "policy_binarypb",
    srcs = [
        "policy.textproto",
        "//avs_server/proto:policy.proto",
        "@oak//proto/attestation:reference_value.proto",
        "@oak//proto/attestation:tcb_version.proto",
        "@oak//proto:digest.proto",
        "@com_google_protobuf//:well_known_type_protos",
        "@com_google_protobuf//:descriptor_proto_srcs",
    ],
    outs = ["policy.binarypb"],
    cmd = "$(location @com_google_protobuf//:protoc) " +
          "--encode=attestation_verification.Policy " +
          "--proto_path=$$(dirname $$(dirname $$(dirname $(location //avs_server/proto:policy.proto)))) " +
          "--proto_path=$$(dirname $$(dirname $$(dirname $(location @oak//proto/attestation:reference_value.proto)))) " +
          "--proto_path=$$(dirname $$(dirname $$(dirname $(location @com_google_protobuf//:descriptor_proto_srcs)))) " +
          "avs_server/proto/policy.proto " +
          "< $(location policy.textproto) " +
          "> $@",
    tools = [
        "@com_google_protobuf//:protoc",
    ],
)

filegroup(
    name = "policy",
    srcs = [
        "policy.textproto",
        ":policy_binarypb",
    ],
)
