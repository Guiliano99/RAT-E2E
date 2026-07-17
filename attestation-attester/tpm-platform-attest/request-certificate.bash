#!/usr/bin/env bash
# request-certificate.bash — interactive TPM-enrollment walkthrough, run via
#   docker exec -it attestation-attester-tpm-platform-attester-1 /app/request-certificate.bash
#
# This is the presentation-only path.  Automated checks must call the separate
# non-interactive /app/e2e-enroll.sh driver instead.
set -Eeuo pipefail

# shellcheck source=/app/entrypoint.sh
source /app/entrypoint.sh

# The walkthrough always captures the CMP nonce exchange for its self-gating
# decoder and enables the native gencmpclient quote renderer.  The legacy
# libattest flag remains set for bridge-based attesters.
export CMP_MSG_CAPTURE=1
export CMP_LOG_ATTEST_STMT=1
export LIBATTEST_LOG_STMT=1

RED=$'\033[0;31m'
GREEN=$'\033[0;32m'
ORANGE=$'\033[0;33m'
NC=$'\033[0m'
CURRENT_STEP="certificate-request walkthrough"

trap 'status=$?; printf "\n%sError: %s failed (exit %d).%s\n" "${RED}" "${CURRENT_STEP}" "${status}" "${NC}" >&2; exit "${status}"' ERR

step_banner() {
    local title="$1"
    shift

    printf '\n'
    printf '#########################################################################\n'
    printf '# %s\n#\n' "${title}"
    local detail
    for detail in "$@"; do
        printf '# %s\n' "${detail}"
    done
    printf '\n'
}

pause_for_operator() {
    printf '%s' "${ORANGE}"
    read -r -p "$1" _
    printf '%s' "${NC}"
}

run_step() {
    local action="$1"
    local prompt="$2"
    shift 2

    CURRENT_STEP="${action}"
    pause_for_operator "${prompt}"
    "$@"
    printf '✅ %s%s complete.%s\n\n' "${GREEN}" "${action}" "${NC}"
}

# Wait for the MockCA and persist its enrollment root for certificate inspection.
poll_mock_ca() {
    local server="${CMP_SERVER:-192.168.100.12:5000}"
    echo "[request-cert] Waiting for MockCA at http://${server}/root-cert ..."

    local attempt
    for attempt in $(seq 1 60); do
        if wget -q -O- "http://${server}/root-cert" 2>/dev/null | base64 -d \
               | openssl x509 -inform der -out "${OUTPUT_DIR}/mockca_root.pem" 2>/dev/null; then
            echo "[request-cert] MockCA ready; enrollment root saved to ${OUTPUT_DIR}/mockca_root.pem"
            return 0
        fi
        sleep 2
    done

    echo "[request-cert] ERROR: MockCA not reachable at ${server} after 120s" >&2
    return 1
}

step_banner "Request a certificate with TPM quote evidence" \
    "📡 Contact the CMP RA to obtain a fresh server-issued nonce." \
    "🛡️ Bind the TPM2_Quote to that nonce before the certificate is issued."
run_step "Contact the MockCA" "Press <ENTER> to wait for the CMP RA ..." poll_mock_ca

step_banner "Prepare the TPM-resident subject key" \
    "🔐 The private key stays in the TPM; only its public key leaves the device." \
    "🧩 The TPM provider is configured only for local key generation."
run_step "Configure the TPM OpenSSL provider" "Press <ENTER> to configure the TPM provider ..." configure_openssl

step_banner "Generate the TPM-resident subject key" \
    "🔐 The private key remains protected by the TPM for the full enrollment." \
    "📄 Only the public key is supplied in the certificate request."
run_step "Generate the TPM-resident subject key" "Press <ENTER> to generate the TPM key ..." generate_tpm_key

step_banner "Submit nonce-bound TPM evidence" \
    "📨 The attester requests a CMP certificate using a TPM2_Quote over the selected PCRs." \
    "🔎 The verifier checks the quote, AK signature, nonce, and PCR policy before issuance." \
    "🧾 cmpClient prints the generated TcgAttestQuote for inspection before it is sent."
run_step "Request the attested certificate" "Press <ENTER> to send the CMP enrollment ..." request_certificate

ENROLLED="${OUTPUT_DIR}/enrolled.pem"
if [ ! -s "${ENROLLED}" ]; then
    CURRENT_STEP="Certificate issuance"
    printf '%sError: CMP enrollment completed without %s.%s\n' "${RED}" "${ENROLLED}" "${NC}" >&2
    exit 1
fi

step_banner "Publish TPM enrollment artefacts" \
    "📁 Store the certificate, public key, and trust material in the output directory." \
    "✅ The TPM private key remains a TPM-wrapped TSS2 key representation."
run_step "Publish enrollment artefacts" "Press <ENTER> to publish the enrollment artefacts ..." publish_artefacts
print_summary

step_banner "Inspect the issued certificate" \
    "💻 The X.509 certificate carries the verifier's EAR result under OID 1.7.6.5.123." \
    "⛔ Failed evidence appraisal prevents certificate issuance."
run_step "Display the issued certificate" "Press <ENTER> to view certificate contents ..." \
    openssl x509 -in "${ENROLLED}" -text -noout

# ── Decode the captured CMP nonce exchange → output/nonce-exchange.txt ─────────
_ppout="${OUTPUT_DIR:-}"
_ppscript="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/pretty_print_stmt.py"
if [ -n "${_ppout}" ] && [ -f "${_ppscript}" ] \
   && [ -f "${_ppout}/req1-genm.der" ] && [ -f "${_ppout}/rsp1-genp.der" ] \
   && python3 -c "import libattest.formats.csrattest.pretty_print_cmp_stmt, pyasn1_alt_modules" 2>/dev/null; then
    if python3 "${_ppscript}" "${_ppout}/req1-genm.der" "${_ppout}/rsp1-genp.der" \
           > "${_ppout}/nonce-exchange.txt" 2>&1; then
        printf '📄 %sDecoded CMP nonce exchange → %s/nonce-exchange.txt%s\n' \
            "${GREEN}" "${_ppout}" "${NC}"
    fi
fi
