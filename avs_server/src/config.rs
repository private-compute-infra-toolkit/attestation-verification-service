//
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
//

use serde::Deserialize;

fn default_use_self_signed_cert() -> bool {
    false
}

fn default_tca_endpoint() -> String {
    "http://10.0.2.100:8008".to_string()
}

#[derive(Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct AppConfig {
    #[serde(default = "default_use_self_signed_cert")]
    pub use_self_signed_cert: bool,
    #[serde(default = "default_tca_endpoint")]
    pub tca_endpoint: String,
}

impl Default for AppConfig {
    fn default() -> Self {
        Self {
            use_self_signed_cert: default_use_self_signed_cert(),
            tca_endpoint: default_tca_endpoint(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_values_applied() {
        let json_str = "{}";
        let config: AppConfig = serde_json::from_str(json_str).unwrap();
        assert!(!config.use_self_signed_cert);
        assert_eq!(config.tca_endpoint, "http://10.0.2.100:8008");
    }

    #[test]
    fn test_custom_values_applied() {
        let json_str = r#"{"use_self_signed_cert": true, "tca_endpoint": "http://example.com"}"#;
        let config: AppConfig = serde_json::from_str(json_str).unwrap();
        assert!(config.use_self_signed_cert);
        assert_eq!(config.tca_endpoint, "http://example.com");
    }

    #[test]
    fn test_legacy_fields_ignored_and_defaults_applied() {
        // "use_tca_cert_chain" is a legacy field and should be ignored.
        // Since "use_self_signed_cert" is missing, it should fallback to default
        // (false).
        let json_str = r#"{"use_tca_cert_chain": true, "tca_endpoint": "http://custom-tca:9000"}"#;
        let config: AppConfig = serde_json::from_str(json_str).unwrap();
        assert!(!config.use_self_signed_cert);
        assert_eq!(config.tca_endpoint, "http://custom-tca:9000");
    }
}
