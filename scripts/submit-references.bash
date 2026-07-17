#!/usr/bin/env bash

set -e

print_usage () {
	echo "Usage: ./submit-references.bash [OPTIONS]"
    echo ""
    echo "Submit (unsigned) CoRIM to the Veraison verifier"
    echo ""
    echo "Options:"
    echo "  -c, --corim     Path to CoRIM to submit"
    echo "  -o, --host      Address of Veraison provisioning service"
    echo "  -p, --port      Port of Veraison provisioning service"
    echo "  -h, --help      Display this help message"
}

# Check that all required commands are available
check_dependencies () {
    # Required commands
    echo "Checking required commands ..."
    for reqcmd in curl; do
        if ! command -v ${reqcmd} > /dev/null 2>&1; then
            echo "Error, command ${reqcmd} not found; please install. Exiting."
            exit 1
        fi
    done
}

check_dependencies

# Basic arg checking
while :; do
    case $1 in
        -h|-\?|--help)  # Help / usage message
            print_usage
            exit
            ;;
        -o|--host)      # Address of Veraison provisioning service
            if [ "$2" ]; then
                host=$2
                shift
            fi
            ;;
        -p|--port)      # Port of Veraison provisioning service
            if [ "$2" ]; then
                port=$2
                shift
            fi
            ;;
        -c|--corim)    # CoRIM to submit
            if [ "$2" ]; then
                corim=$2
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

if [ ! -e "${corim}" ]; then
    echo "Invalid path to CoRIM specified... Exiting."
    exit 1
fi

if [ -z "${host}" ] || [ -z "${port}" ]; then
    echo "Please specify Veraison provisioning service address and port... Exiting."
    exit 1
fi

curl --insecure --data-binary "@./attestation-attester/sw-runtime/persistent-data/references/corim.cbor" \
    -H "Content-Type: application/corim-unsigned+cbor; profile=\"http://siemens.com/attestation/atg-demo/1\"" \
    -H "Accept: application/vnd.veraison.provisioning-session+json" \
    -X POST https://${host}:${port}/endorsement-provisioning/v1/submit
echo ""
