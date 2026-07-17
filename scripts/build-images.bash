#!/usr/bin/env bash

set -e

print_usage () {
	echo "Usage: ./build-images.bash [OPTIONS]"
    echo ""
    echo "Build all images, using a supplied tag"
    echo ""
    echo "Options:"
    echo "  -t, --tag       Tag to use for the generated images"
    echo "  -r, --reg       Registry path"
    echo "  -h, --help      Display this help message"
}

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

# Basic arg checking
tag=""
reg_path=""
while :; do
    case $1 in
        -h|-\?|--help)  # Help / usage message
            print_usage
            exit
            ;;
        -t|--tag)      # Tag to use for the generated images
            if [ "$2" ]; then
                tag=$2
                shift
            fi
            ;;
        -r|--reg)      # Registry path
            if [ "$2" ]; then
                reg_path=$2
                shift
            fi
            ;;
        -?*)            # Unknown arg
            echo "ERROR: Unknown argument"
            print_usage
            exit
            ;;
        *)              # No more options
            break
    esac 
    shift
done

if [ -z ${tag} ]; then
    tag=latest
fi
if [ -z ${reg_path} ]; then
    reg_path="remote-attestation-demonstration-environment"
fi

# Build attester images
(
    cd attestation-attester
    REG_PATH=${reg_path} IMG_TAG=${tag} docker compose build
)

# Build infrastructure images
(
    cd attestation-infra
    REG_PATH=${reg_path} IMG_TAG=${tag} docker compose build
)