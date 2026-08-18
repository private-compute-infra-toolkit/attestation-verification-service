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

//! Build tool that combines multiple `Policy` binarypb files into a single
//! `PolicyBundle` binarypb file.

use avs_proto_rust::avs::{Policy, PolicyBundle};
use prost::Message;

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 2 {
        eprintln!("Usage: {} <output.binarypb> [<input1.binarypb> ...]", args[0]);
        std::process::exit(1);
    }

    let output_path = &args[1];
    let input_paths = &args[2..];

    let policies: Vec<Policy> = input_paths
        .iter()
        .map(|path| {
            let bytes =
                std::fs::read(path).unwrap_or_else(|e| panic!("failed to read {path}: {e}"));
            Policy::decode(bytes.as_slice())
                .unwrap_or_else(|e| panic!("failed to decode policy from {path}: {e}"))
        })
        .collect();

    let bundle = PolicyBundle { policies };
    let mut encoded = Vec::new();
    bundle.encode(&mut encoded).expect("failed to encode PolicyBundle");

    std::fs::write(output_path, encoded)
        .unwrap_or_else(|e| panic!("failed to write {output_path}: {e}"));
}
