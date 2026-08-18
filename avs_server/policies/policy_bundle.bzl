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

"""Bazel macros for AVS policy compilation and bundling."""

def policy_binarypb(name, textproto = "policy.textproto", visibility = None, **kwargs):
    """Compiles a Policy textproto into a binarypb file.

    Args:
        name: Target name (conventionally "policy_binarypb").
        textproto: The policy textproto source file.
        visibility: Bazel visibility.
        **kwargs: Additional arguments passed to genrule.
    """
    native.genrule(
        name = name,
        srcs = [
            textproto,
            "//avs_server/proto:policy.proto",
            "@oak//proto/attestation:reference_value.proto",
            "@oak//proto/attestation:tcb_version.proto",
            "@oak//proto:digest.proto",
            "@com_google_protobuf//:well_known_type_protos",
            "@com_google_protobuf//:descriptor_proto_srcs",
        ],
        outs = ["policy.binarypb"],
        cmd = (
            "$(location @com_google_protobuf//:protoc) " +
            "--encode=attestation_verification.Policy " +
            "--proto_path=$$(dirname $$(dirname $$(dirname $(location //avs_server/proto:policy.proto)))) " +
            "--proto_path=$$(dirname $$(dirname $$(dirname $(location @oak//proto/attestation:reference_value.proto)))) " +
            "--proto_path=$$(dirname $$(dirname $$(dirname $(location @com_google_protobuf//:descriptor_proto_srcs)))) " +
            "avs_server/proto/policy.proto " +
            "< $(location " + textproto + ") " +
            "> $@"
        ),
        tools = [
            "@com_google_protobuf//:protoc",
        ],
        visibility = visibility,
        **kwargs
    )

def policy_bundle(name, policies, visibility = None, **kwargs):
    """Combines multiple policy binarypb files into a PolicyBundle binarypb.

    Args:
        name: Target name (e.g. "policy_bundle"). Output file will be <name>.binarypb.
        policies: List of policy_binarypb targets to include.
        visibility: Bazel visibility.
        **kwargs: Additional arguments passed to genrule.
    """
    native.genrule(
        name = name,
        srcs = policies,
        outs = [name + ".binarypb"],
        cmd = "$(location //avs_server/policies:bundle_policies) $@ $(SRCS)",
        tools = ["//avs_server/policies:bundle_policies"],
        visibility = visibility,
        **kwargs
    )
