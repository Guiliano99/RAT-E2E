#!/usr/bin/env bash

echo "Cleaning up Docker networks..."
docker network rm infra-ra infra-verifier provisioning 2>/dev/null

echo "Cleaning up Docker volume..."
docker volume rm tpm-ca 2>/dev/null

echo "Cleanup complete."