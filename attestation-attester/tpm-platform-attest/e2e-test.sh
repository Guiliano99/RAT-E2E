#!/usr/bin/env bash
# e2e-test.sh — End-to-end smoke test for the TPM platform-attestation demo.
#
# Brings up the two Compose projects (attester + infra) the same way a user does
# (configure-network + two `docker compose up` + the external tpm-ca volume),
# then drives ONE positive and ONE negative enrolment through the dedicated
# non-interactive /app/e2e-enroll.sh driver.  The operator-facing
# request-certificate.bash walkthrough is deliberately never run in CI.
#
# Usage:
#   ./e2e-test.sh                 # run positive + negative
#   ./e2e-test.sh --build         # rebuild images first
#   ./e2e-test.sh --positive-only # run only the positive case
#   ./e2e-test.sh --negative-only # run only the negative case
#   ./e2e-test.sh --keep          # do not tear down at the end
#
# Checks (simple positive + one negative):
#   POSITIVE  enrol issues a certificate that parses, chains to the demo CA,
#             whose SPKI matches the TPM-resident subject key, and carries the
#             EAR (attestation result) extension 1.7.6.5.123.
#   NEGATIVE  a corrupted AK signature (CMP_BAD_ATTEST_SIG=1) is refused: the
#             enrolment exits non-zero and no certificate is written.

set -uo pipefail

# ─── Configuration ───────────────────────────────────────────────────────────

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "${SCRIPT_DIR}"

OUTPUT_DIR="${SCRIPT_DIR}/output"
ATTESTER_SERVICE="tpm-platform-attester"
CONTAINER_LOG_TIMEOUT="${CONTAINER_LOG_TIMEOUT:-180}"  # seconds

# ─── Output helpers ──────────────────────────────────────────────────────────

if [[ -t 1 ]]; then
    C_RED=$'\033[0;31m'
    C_GREEN=$'\033[0;32m'
    C_YELLOW=$'\033[0;33m'
    C_BLUE=$'\033[0;34m'
    C_BOLD=$'\033[1m'
    C_RESET=$'\033[0m'
else
    C_RED=""; C_GREEN=""; C_YELLOW=""; C_BLUE=""; C_BOLD=""; C_RESET=""
fi

log_info()    { printf '%s[INFO]%s  %s\n' "${C_BLUE}" "${C_RESET}" "$*"; }
log_warn()    { printf '%s[WARN]%s  %s\n' "${C_YELLOW}" "${C_RESET}" "$*"; }
log_error()   { printf '%s[ERROR]%s %s\n' "${C_RED}" "${C_RESET}" "$*" >&2; }
log_section() { printf '\n%s%s━━━ %s ━━━%s\n' "${C_BOLD}" "${C_BLUE}" "$*" "${C_RESET}"; }

# Result tracking — populated by the run_*() functions, summarised at the end.
declare -A RESULTS
declare -A RESULT_NOTES
RESULT_ORDER=()

record_pass() {
    local key="$1" note="${2:-}"
    RESULTS["$key"]="PASS"
    RESULT_NOTES["$key"]="${note}"
    RESULT_ORDER+=("$key")
    printf '  %s✓%s %s%s\n' "${C_GREEN}" "${C_RESET}" "$key" "${note:+ — ${note}}"
}

record_fail() {
    local key="$1" note="${2:-}"
    RESULTS["$key"]="FAIL"
    RESULT_NOTES["$key"]="${note}"
    RESULT_ORDER+=("$key")
    printf '  %s✗%s %s%s\n' "${C_RED}" "${C_RESET}" "$key" "${note:+ — ${note}}"
}

# ─── Argument parsing ────────────────────────────────────────────────────────

BUILD=0
RUN_POSITIVE=1
RUN_NEGATIVE=1
KEEP=0

while [[ $# -gt 0 ]]; do
    case "$1" in
        --build)         BUILD=1 ;;
        --positive-only) RUN_NEGATIVE=0 ;;
        --negative-only) RUN_POSITIVE=0 ;;
        --keep)          KEEP=1 ;;
        -h|--help)
            sed -n '2,/^set/p' "$0" | sed 's/^# \?//'
            exit 0 ;;
        *) log_error "Unknown argument: $1"; exit 2 ;;
    esac
    shift
done

# ─── Docker compose helpers ──────────────────────────────────────────────────

# The attester and infra compose files run as two SEPARATE projects that
# interconnect over the external bridges + external tpm-ca volume created by
# scripts/configure-network.bash (mirroring the sw-runtime EAR demo).  The
# long-lived attester enrols on demand via the non-interactive e2e-enroll.sh driver.
ATTESTER_COMPOSE="${SCRIPT_DIR}/../docker-compose.yml"
INFRA_COMPOSE="${SCRIPT_DIR}/../../attestation-infra/docker-compose.yml"
PROJ_ATT="tpm-att"
PROJ_INF="tpm-inf"
dca() { docker compose -p "${PROJ_ATT}" -f "${ATTESTER_COMPOSE}" "$@"; }
dci() { docker compose -p "${PROJ_INF}" -f "${INFRA_COMPOSE}" "$@"; }

setup_external() {
    # Idempotent: create the shared bridges + tpm-ca volume (ignore "exists").
    "${SCRIPT_DIR}/../../scripts/configure-network.bash" >/dev/null 2>&1 || true
    docker volume create tpm-ca >/dev/null 2>&1 || true
}

teardown() {
    log_info "Tearing down both projects..."
    dci down -v --remove-orphans 2>/dev/null || true
    dca down -v --remove-orphans 2>/dev/null || true
    docker volume rm tpm-ca >/dev/null 2>&1 || true
}

if [[ "${KEEP}" -eq 0 ]]; then
    trap teardown EXIT
fi

wait_for_file() {
    local path="$1" timeout="${2:-${CONTAINER_LOG_TIMEOUT}}"
    local elapsed=0
    while [[ ! -f "${path}" ]] && [[ "${elapsed}" -lt "${timeout}" ]]; do
        sleep 2
        elapsed=$(( elapsed + 2 ))
    done
    [[ -f "${path}" ]]
}

# ─── Build images (optional) ─────────────────────────────────────────────────

setup_external

if [[ "${BUILD}" -eq 1 ]]; then
    log_section "Rebuilding images"
    dca build --pull
    dci build --pull
fi

# ─── Bring up both projects ──────────────────────────────────────────────────

log_section "Starting both Compose projects"
# Attester project first (simulator → provisioner writes tpm-ca → attester idles),
# then the infra project (tpm-verifier → mock-ca).
log_info "Bringing up attester project (${PROJ_ATT})..."
dca up -d
log_info "Bringing up infra project (${PROJ_INF})..."
dci up -d

# Wait for mock-ca and tpm-verifier (infra project) to report healthy.
log_info "Waiting for mock-ca and tpm-verifier to become healthy..."
healthy_timeout=180
healthy_elapsed=0
while [[ "${healthy_elapsed}" -lt "${healthy_timeout}" ]]; do
    mock_health="$(docker inspect --format '{{.State.Health.Status}}' \
        "$(dci ps -q mock-ca 2>/dev/null)" 2>/dev/null || echo "unknown")"
    verif_health="$(docker inspect --format '{{.State.Health.Status}}' \
        "$(dci ps -q tpm-verifier 2>/dev/null)" 2>/dev/null || echo "unknown")"
    if [[ "${mock_health}" == "healthy" && "${verif_health}" == "healthy" ]]; then
        log_info "All infra services healthy."
        break
    fi
    sleep 3
    healthy_elapsed=$(( healthy_elapsed + 3 ))
done
if [[ "${mock_health:-}" != "healthy" || "${verif_health:-}" != "healthy" ]]; then
    log_error "Dependencies did not become healthy within ${healthy_timeout}s"
    log_error "  mock-ca: ${mock_health:-unknown}, tpm-verifier: ${verif_health:-unknown}"
    log_error "Container states:"
    dca ps -a || true
    dci ps -a || true
    for svc in mock-ca tpm-verifier; do
        log_error "Last 30 log lines of ${svc}:"
        dci logs --no-color --tail 30 "${svc}" 2>&1 || true
    done
    exit 1
fi

# The long-lived attester (attester project) must be running before we exec the
# enrolment into it; it starts once the provisioner has completed.
log_info "Waiting for the attester container to be running..."
att_elapsed=0
while [[ "${att_elapsed}" -lt 120 ]]; do
    if dca ps --status running --format '{{.Service}}' 2>/dev/null | grep -qx "${ATTESTER_SERVICE}"; then
        log_info "Attester container is running."
        break
    fi
    sleep 3
    att_elapsed=$(( att_elapsed + 3 ))
done
if ! dca ps --status running --format '{{.Service}}' 2>/dev/null | grep -qx "${ATTESTER_SERVICE}"; then
    log_error "Attester container not running after 120s — provisioner may have failed:"
    dca ps -a || true
    dca logs --no-color --tail 40 provisioner 2>&1 || true
    dca logs --no-color --tail 40 "${ATTESTER_SERVICE}" 2>&1 || true
    exit 1
fi

# ─── Positive test ───────────────────────────────────────────────────────────

run_positive_test() {
    log_section "Positive test: well-formed AK signature → cert issued"

    rm -f "${OUTPUT_DIR}/enrolled.pem"

    log_info "Enrolling via docker exec ${ATTESTER_SERVICE} /app/e2e-enroll.sh..."
    local enrol_out enrol_rc=0
    enrol_out="$(dca exec -e "CMP_MSG_CAPTURE=${CMP_MSG_CAPTURE:-0}" -T "${ATTESTER_SERVICE}" /app/e2e-enroll.sh 2>&1)" || enrol_rc=$?
    printf '%s\n' "${enrol_out}"
    if [[ "${enrol_rc}" != "0" ]] || ! wait_for_file "${OUTPUT_DIR}/enrolled.pem" 30; then
        record_fail "POS:cert issued" "e2e-enroll.sh failed or no enrolled.pem (rc=${enrol_rc})"
        return 1
    fi

    # ── A parseable certificate was issued ───────────────────────────────────
    local cert_subject
    cert_subject="$(openssl x509 -noout -subject -in "${OUTPUT_DIR}/enrolled.pem" 2>/dev/null | sed 's/^subject=//')"
    if [[ -n "${cert_subject}" ]]; then
        record_pass "POS:cert issued" "subject: ${cert_subject}"
    else
        record_fail "POS:cert issued" "openssl x509 failed to parse the issued cert"
    fi

    # ── The cert chains to the MockCA enrolment root ─────────────────────────
    # mockca_root.pem is saved by request-certificate.bash; it is the enrolment
    # CA that signs enrolled.pem (NOT ca_cert.pem, which is the attestation AK CA).
    if [[ -f "${OUTPUT_DIR}/mockca_root.pem" ]] \
       && openssl verify -CAfile "${OUTPUT_DIR}/mockca_root.pem" "${OUTPUT_DIR}/enrolled.pem" >/dev/null 2>&1; then
        record_pass "POS:cert signed by CA" "openssl verify OK against output/mockca_root.pem"
    else
        record_fail "POS:cert signed by CA" "openssl verify failed (or output/mockca_root.pem missing)"
    fi

    # ── The cert's SPKI matches the TPM-resident subject key ─────────────────
    if [[ -f "${OUTPUT_DIR}/tpm_key.pub.pem" ]]; then
        local cert_spki tpm_spki
        cert_spki="$(openssl x509 -in "${OUTPUT_DIR}/enrolled.pem" -pubkey -noout 2>/dev/null \
                     | openssl pkey -pubin -outform DER 2>/dev/null | openssl dgst -sha256 -hex 2>/dev/null | awk '{print $NF}')"
        tpm_spki="$(openssl pkey -in "${OUTPUT_DIR}/tpm_key.pub.pem" -pubin -outform DER 2>/dev/null \
                    | openssl dgst -sha256 -hex 2>/dev/null | awk '{print $NF}')"
        if [[ -n "${cert_spki}" && "${cert_spki}" == "${tpm_spki}" ]]; then
            record_pass "POS:cert SPKI matches TPM key" "sha256(SPKI)=${cert_spki:0:16}..."
        else
            record_fail "POS:cert SPKI matches TPM key" "cert=${cert_spki:0:16}... tpm=${tpm_spki:0:16}..."
        fi
    else
        record_fail "POS:cert SPKI matches TPM key" "output/tpm_key.pub.pem missing"
    fi

    # ── The attestation result (EAR) is embedded in the cert ─────────────────
    # Match either spelling: a stock OpenSSL does not know the OID and prints it
    # dotted, while the demo's fork resolves it to its long name. Matching only
    # one would fail a perfectly good certificate depending on which openssl is
    # first on PATH.
    if openssl x509 -in "${OUTPUT_DIR}/enrolled.pem" -text -noout 2>/dev/null \
        | grep -qE '1\.7\.6\.5\.123|EAR Attestation Result'; then
        record_pass "POS:cert carries EAR extension" "1.7.6.5.123 present"
    else
        record_fail "POS:cert carries EAR extension" "1.7.6.5.123 missing"
    fi

    return 0
}

# ─── Negative test ───────────────────────────────────────────────────────────

run_negative_test() {
    log_section "Negative test: corrupted AK signature → cert refused"

    rm -f "${OUTPUT_DIR}/enrolled.pem"

    log_info "Enrolling via docker exec with CMP_BAD_ATTEST_SIG=1 (cmpClient should fail)..."
    local neg_out exit_code=0
    neg_out="$(dca exec -e CMP_BAD_ATTEST_SIG=1 -T "${ATTESTER_SERVICE}" /app/e2e-enroll.sh 2>&1)" || exit_code=$?
    printf '%s\n' "${neg_out}"

    # Pass criteria (robust): the enrolment fails AND no certificate is written.
    if [[ "${exit_code}" != "0" ]]; then
        record_pass "NEG:enrolment fails (non-zero)" "e2e-enroll.sh exit code: ${exit_code}"
    else
        record_fail "NEG:enrolment fails (non-zero)" "e2e-enroll.sh unexpectedly succeeded"
    fi

    if [[ ! -f "${OUTPUT_DIR}/enrolled.pem" ]]; then
        record_pass "NEG:no cert produced" "enrolled.pem absent"
    else
        record_fail "NEG:no cert produced" "enrolled.pem unexpectedly present"
    fi

    # Informational only (not a pass criterion): the CA's wire verdict.
    if printf '%s\n' "${neg_out}" | grep -qE 'PKIFailureInfo:[[:space:]]*badMessageCheck'; then
        log_info "CA wire verdict observed: PKIFailureInfo: badMessageCheck"
    fi

    return 0
}

# ─── Run tests ───────────────────────────────────────────────────────────────

if [[ "${RUN_POSITIVE}" -eq 1 ]]; then
    run_positive_test || true
fi

if [[ "${RUN_NEGATIVE}" -eq 1 ]]; then
    run_negative_test || true
fi

# ─── Summary ─────────────────────────────────────────────────────────────────

log_section "Summary"

total=0; pass=0; fail=0
for key in "${RESULT_ORDER[@]}"; do
    total=$(( total + 1 ))
    if [[ "${RESULTS[$key]}" == "PASS" ]]; then
        pass=$(( pass + 1 ))
        printf '  %s✓ %-44s%s\n' "${C_GREEN}" "${key}" "${C_RESET}"
    else
        fail=$(( fail + 1 ))
        printf '  %s✗ %-44s%s  %s\n' "${C_RED}" "${key}" "${C_RESET}" "${RESULT_NOTES[$key]}"
    fi
done

printf '\n  Total: %d   Passed: %s%d%s   Failed: %s%d%s\n' \
    "${total}" \
    "${C_GREEN}" "${pass}" "${C_RESET}" \
    "${C_RED}" "${fail}" "${C_RESET}"

if [[ "${fail}" -gt 0 ]]; then
    printf '\n%sE2E test FAILED.%s\n' "${C_RED}${C_BOLD}" "${C_RESET}"
    exit 1
fi
printf '\n%sE2E test PASSED.%s\n' "${C_GREEN}${C_BOLD}" "${C_RESET}"
exit 0
