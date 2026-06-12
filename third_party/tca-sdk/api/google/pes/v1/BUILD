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

load("@rules_proto//proto:defs.bzl", "proto_library")

package(default_visibility = ["//visibility:public"])

proto_library(
    name = "endorsement_proto",
    srcs = ["endorsement.proto"],
    deps = [
        "//google/pes/v1:verification_material_proto",
        "@googleapis//google/api:field_behavior_proto",
    ],
)

proto_library(
    name = "verification_material_proto",
    srcs = ["verification_material.proto"],
    deps = [
        "@googleapis//google/api:field_behavior_proto",
    ],
)

proto_library(
    name = "public_endorsement_service_proto",
    srcs = [
        "endorsement.proto",
        "public_endorsement_service.proto",
    ],
    deps = [
        "//google/pes/v1:verification_material_proto",
        "@googleapis//google/api:annotations_proto",
        "@googleapis//google/api:client_proto",
        "@googleapis//google/api:field_behavior_proto",
    ],
)
