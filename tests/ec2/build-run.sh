#!/bin/bash

#
# Build and run the Enclave
#

# Copy nsm-cli binary
cp ../../target/x86_64-unknown-linux-musl/release/nsm-cli .

# Cleanup
nitro-cli terminate-enclave --all

# Build EIF
docker build -t nsm-cli-test -f Dockerfile .
nitro-cli build-enclave --docker-uri nsm-cli-test --output-file nsm-cli-test.eif

# Run and attach console
nitro-cli run-enclave --cpu-count 2 --memory 512 --enclave-cid 5 --eif-path nsm-cli-test.eif --debug-mode

ID=$(nitro-cli describe-enclaves | jq -r '.[0].EnclaveID')
nitro-cli console --enclave-id $ID