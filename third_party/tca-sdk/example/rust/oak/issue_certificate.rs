// Copyright 2026 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

use rsa::sha2::Sha256;
use rsa::{pkcs1v15::SigningKey, RsaPrivateKey};
use std::str::FromStr;
use tca_common::{Csr, TcaClient};
use tca_oak::OakTcaClient;
use x509_cert::builder::{Builder, RequestBuilder};
use x509_cert::der::Encode;
use x509_cert::name::Name;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // 1. Configuration
    // Point this to the TCA service or a local proxy (e.g., "http://10.0.2.2:8080")
    let tca_endpoint = "http://10.0.2.2:8080";

    // 2. Initialize the Client
    // OakTcaClient automatically handles attestation evidence collection
    // and gRPC communication.
    println!("Initializing Oak TCA Client...");
    let client = OakTcaClient::create(tca_endpoint).await?;

    // 3. Generate a Certificate Signing Request (CSR)
    println!("Generating Key Pair and CSR...");
    let mut rng = rand::rngs::OsRng;
    let private_key = RsaPrivateKey::new(&mut rng, 4096)?;
    let signing_key = SigningKey::<Sha256>::new(private_key);

    let subject = Name::from_str("CN=MyOakWorkload, O=MyOrg")?;
    let builder = RequestBuilder::new(subject, &signing_key)?;

    let csr = builder.build::<rsa::pkcs1v15::Signature>()?;
    let csr_der = csr.to_der()?;

    // 4. Issue the Certificate
    println!("Requesting Certificate from TCA...");
    let response = client.issue_certificate(Csr(csr_der)).await?;

    // 5. Use the Certificate
    println!("Received Certificate Chain with {} certificates.", response.0.len());
    if let Some(leaf_cert) = response.0.first() {
        println!("Leaf Certificate size: {} bytes", leaf_cert.0.len());
    }

    Ok(())
}
