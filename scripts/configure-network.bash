#!/usr/bin/env bash

# Check that all required commands are available
check_dependencies () {
    # Required commands
    echo "Checking required commands ..."
    for reqcmd in docker; do
        if ! command -v ${reqcmd} > /dev/null 2>&1; then
            echo "Error, command ${reqcmd} not found; please install. Exiting."
            exit 1
        fi
    done
}

check_dependencies

docker network create \
    --driver bridge \
    --subnet 192.168.100.0/24 \
    --gateway 192.168.100.1 \
    infra-ra

docker network create \
    --driver bridge \
    --subnet 192.168.110.0/24 \
    --gateway 192.168.110.1 \
    infra-verifier

docker network create \
    --driver bridge \
    --subnet 192.168.200.0/24 \
    --gateway 192.168.200.1 \
    provisioning

# Shared external volume for the TPM demo's CA keypair / AK cert / PCR reference,
# written by the attester-side provisioner and read by the infra-side verifier.
# External so the two separate Compose projects (attester / infra) share it.
docker volume create tpm-ca

