# Copyright 2025 Google LLC
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
    name = "entry_proto",
    srcs = ["entry.proto"],
    deps = [
        "@googleapis//google/api:field_behavior_proto",
    ],
)

proto_library(
    name = "transparent_ledger_proto",
    srcs = [
        "entry.proto",
        "transparent_ledger.proto",
    ],
    deps = [
        "@googleapis//google/api:annotations_proto",
        "@googleapis//google/api:client_proto",
        "@googleapis//google/api:field_behavior_proto",
    ],
)
