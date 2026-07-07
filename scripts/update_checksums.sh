#!/bin/bash
#
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
#

set -o errexit
set -o nounset

if [[ -z "${BUILD_WORKSPACE_DIRECTORY:-}" ]]; then
  >&2 echo "BUILD_WORKSPACE_DIRECTORY not set"
  >&2 echo "Did you invoke this script directly?"
  exit 2
fi
cd "${BUILD_WORKSPACE_DIRECTORY}"

exec ./devkit/check_checksums --update "$@"
