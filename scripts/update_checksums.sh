#!/bin/bash
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
#
# Updates checksums.txt based on the current build state. Don't execute
# this script directly; instead, invoke it using the following command:
#
# devkit/build bazel run //:update_checksums
#
# The diff is displayed and applied. If nothing is shown, there has
# been no change in checksums.
set -e
set -o pipefail

readonly CHKFILE=checksums.txt

if [[ -z "${BUILD_WORKSPACE_DIRECTORY}" ]]; then
  >&2 echo "BUILD_WORKSPACE_DIRECTORY not set"
  >&2 echo "Did you invoke this script directly?"
  exit 2
fi
cd "${BUILD_WORKSPACE_DIRECTORY}"

# Compute new checksums.
new_contents="$(awk '{print $2}' "${CHKFILE}" | xargs sha256sum)"

# Present the diff to the caller.
echo "${new_contents}" | diff --color=always -u "${CHKFILE}" - || [ $? -eq 1 ]

# Apply the update.
echo "${new_contents}" > "${CHKFILE}"
