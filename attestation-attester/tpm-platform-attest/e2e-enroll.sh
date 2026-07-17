#!/usr/bin/env bash
# e2e-enroll.sh — non-interactive TPM platform-attestation enrolment driver.
#
# This is intentionally distinct from request-certificate.bash.  CI and e2e
# gates call this script without a TTY; the presentation walkthrough always
# pauses for an operator and must therefore never be used by automation.
set -euo pipefail

# shellcheck source=/app/entrypoint.sh
source /app/entrypoint.sh

# Wait for the MockCA and persist its enrollment root for the e2e chain check.
poll_mock_ca() {
    local server="${CMP_SERVER:-192.168.100.12:5000}"
    echo "[e2e-enroll] Waiting for MockCA at http://${server}/root-cert ..."

    local attempt
    for attempt in $(seq 1 60); do
        if wget -q -O- "http://${server}/root-cert" 2>/dev/null | base64 -d \
               | openssl x509 -inform der -out "${OUTPUT_DIR}/mockca_root.pem" 2>/dev/null; then
            echo "[e2e-enroll] MockCA ready; enrollment root saved to ${OUTPUT_DIR}/mockca_root.pem"
            return 0
        fi
        sleep 2
    done

    echo "[e2e-enroll] ERROR: MockCA not reachable at ${server} after 120s" >&2
    return 1
}

poll_mock_ca
configure_openssl
generate_tpm_key
request_certificate

if [ ! -s "${OUTPUT_DIR}/enrolled.pem" ]; then
    echo "[e2e-enroll] ERROR: CMP enrolment returned without ${OUTPUT_DIR}/enrolled.pem" >&2
    exit 1
fi

publish_artefacts
print_summary
