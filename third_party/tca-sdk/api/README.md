# PCIT API

This repository contains the API definitions in Protocol Buffers (proto) format for the Private
Compute Infrastructure Toolikt services.

## Overview

The API definitions serve as the shared contract between PCIT services and their clients. The
repository is designed to be imported as a dependency by both client-side and server-side projects.

## Usage

This repository provides standard Bazel `proto_library()` targets. Language-specific libraries
(e.g., Java, Python, C++) generated from these protos should be defined within the repositories that
consume this project.

## WARNING: Unstable

**The API is currently experimental and unstable. Backward compatibility is not guaranteed.**
