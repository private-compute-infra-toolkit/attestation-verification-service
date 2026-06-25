// Copyright 2026 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

use anyhow::{Context, Result};
use glob::glob;

/// Loads all certificates matching the specified glob pattern.
/// Returns a vector of strings, each containing the content of a certificate
/// file.
pub fn load_certificates(glob_pattern: &str) -> Result<Vec<String>> {
    let mut certs = Vec::new();

    for entry in glob(glob_pattern).context("Failed to parse certificate glob pattern")? {
        let path = entry.context("Failed to resolve glob entry")?;
        if path.is_file() {
            let content = std::fs::read_to_string(&path)
                .with_context(|| format!("Failed to read certificate file {:?}", path))?;
            certs.push(content);
        }
    }
    Ok(certs)
}
