//
// Copyright 2025 Google LLC
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

use anyhow::Context;
use avs_proto_rust::avs::attestation_verification_server::AttestationVerificationServer;
use avs_server_lib::server::AttestationVerificationService;
use log::info;
use oak_sdk_containers::{default_orchestrator_channel, OrchestratorClient};
use serde::Deserialize;
use std::sync::Arc;
use tca_common::TcaClient;
use tca_oak::OakTcaClient;
use tonic::transport::Server;
use tonic::Status;

#[derive(Deserialize)]
struct AppConfig {
    #[serde(default)]
    use_tca_cert_chain: bool,
    #[serde(default)]
    tca_endpoint: String,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info"))
        .format_timestamp(None)
        .write_style(env_logger::WriteStyle::Never)
        .init();
    info!("AVS: Starting main...");
    info!("AVS: Building orchestrator channel");
    let orchestrator_channel =
        default_orchestrator_channel().await.context("failed to create orchestrator channel")?;

    info!("AVS: Building orchestrator client");
    let mut orchestrator_client = OrchestratorClient::create(&orchestrator_channel);

    let config_string = String::from_utf8(orchestrator_client.get_application_config().await?)?;
    info!("AVS: Application config string: {}", config_string);
    let config: AppConfig =
        serde_json::from_str(&config_string).context("failed to parse application config")?;

    info!("AVS: use_tca_cert_chain: {}", config.use_tca_cert_chain);

    info!("AVS: Creating AttestationVerificationService");
    let tca_client: Option<Arc<dyn TcaClient>> = if config.use_tca_cert_chain {
        let tca_endpoint = config.tca_endpoint;
        info!("AVS: TCA endpoint: \"{}\"", tca_endpoint);
        info!("AVS: Initializing OakTcaClient...");
        let tca_client = Arc::new(
            OakTcaClient::create(&tca_endpoint)
                .await
                .map_err(|e| Status::internal(format!("Failed to create tca_client: {}", e)))?,
        );
        info!("AVS: OakTcaClient initialized.");
        Some(tca_client)
    } else {
        None
    };

    let attestation_verification_service = AttestationVerificationService::new(tca_client);
    info!("AVS: AttestationVerificationService created.");

    info!("AVS: Building gRPC server...");
    let addr = "[::]:8080".parse()?;
    let server = Server::builder()
        .add_service(AttestationVerificationServer::new(attestation_verification_service))
        .serve(addr);

    info!("AVS: Notifying orchestrator client");
    orchestrator_client.notify_app_ready().await.context("failed to notify that app is ready")?;

    info!("AVS: AVS enclave is listening on {}", addr);

    info!("AVS: Starting server future...");
    server.await?;

    info!("AVS: Server execution finished.");
    Ok(())
}
