#!/usr/bin/env bash
# entrypoint.sh — TPM key generation and CMP IR enrollment (Phase 4)
#
# Assumes provision.sh (run by the provisioner service) has already:
#   - Persisted EK at 0x81010001 and AK at 0x81010002
#   - Written /tpm-ca/ca_cert.pem and /tpm-ca/ak_cert.pem
#
# Flow:
#   1. TPM2_Startup(CLEAR) — wait for the simulator and initialize the TPM.
#      Persistent handles survive CLEAR startup (NV is preserved per spec).
#   2. Verify provisioner artefacts (persistent handles + AK cert present).
#   3. Configure and activate the tpm2-openssl provider.
#   4. Generate a TPM-resident RSA-2048 subject key via `openssl genpkey`.
#      Export its plain public key PEM for use in the CMP certRequest.
#   5. CMP IR: UNSET OPENSSL_CONF so the tpm2-openssl provider is NOT loaded
#      in the cmpClient process.  All TPM operations (Esys_Certify) go through
#      the in-process tpm_ops.c path driven by -tpm_ak_handle.
#   6. Publish artefacts to /output (bind-mounted from ./output/ on the host).
set -euo pipefail

TCTI="${TPM2TOOLS_TCTI:-mssim:host=simulator,port=2321}"
export TPM2TOOLS_TCTI="${TCTI}"
OPENSSL_TCTI="${TPM2OPENSSL_TCTI:-${TCTI}}"

SRK_HANDLE="0x81000001"
AK_HANDLE="0x81010002"
CA_DIR="/tpm-ca"
WORK_DIR="/tmp/tpm-attest"
OUTPUT_DIR="/output"
mkdir -p "${WORK_DIR}" "${OUTPUT_DIR}"

RM_TCTI=""   # set by start_resource_manager() to the tabrmd TCTI string

# Start a tpm2-abrmd resource manager (on a private D-Bus) that connects to the
# remote mssim simulator and multiplexes it.  Needed only for CMP_POPO=1, where
# the tpm2 provider (POPO signing) and tpm_ops.c (in-process quote) must hold
# concurrent TPM connections that the single-session simulator cannot give them
# directly.  Idempotent: a second call is a no-op once RM_TCTI is set.
start_resource_manager() {
    [ -n "${RM_TCTI}" ] && return 0
    echo "[entrypoint] Starting tpm2-abrmd resource manager (→ ${TCTI})..."
    # D-Bus needs a valid 32-hex machine-id and a runtime dir before the system
    # bus (and abrmd's name ownership) will come up.  Base images often ship an
    # EMPTY /etc/machine-id, which `--ensure` does not repair, so write one.
    [ -s /etc/machine-id ] || dbus-uuidgen > /etc/machine-id
    mkdir -p /var/lib/dbus
    dbus-uuidgen --ensure                 # mirror into /var/lib/dbus/machine-id
    mkdir -p /run/dbus
    rm -f /run/dbus/pid
    dbus-daemon --system --fork
    tpm2-abrmd --allow-root --tcti="${TCTI}" &
    local i
    for i in $(seq 1 60); do
        if TPM2TOOLS_TCTI="tabrmd" tpm2_getcap properties-fixed >/dev/null 2>&1; then
            RM_TCTI="tabrmd"
            echo "[entrypoint] tpm2-abrmd ready (tcti=${RM_TCTI})"
            return 0
        fi
        sleep 0.5
    done
    echo "[entrypoint] ERROR: tpm2-abrmd did not become ready" >&2
    exit 1
}

# ── Step 1: wait for simulator + TPM2_Startup(CLEAR) ─────────────────────────
tpm_startup() {
    local retries=40
    echo "[entrypoint] Waiting for TPM simulator and sending TPM2_Startup(CLEAR)..."
    while [ "${retries}" -gt 0 ]; do
        if tpm2_startup -c 2>/dev/null; then
            echo "[entrypoint] TPM startup complete"
            return 0
        fi
        sleep 1
        retries=$(( retries - 1 ))
    done
    echo "[entrypoint] ERROR: TPM startup failed after 40 s" >&2
    exit 1
}

# ── Step 2: verify provisioner artefacts ─────────────────────────────────────
# The provisioner service must have completed (docker-compose depends_on with
# condition: service_completed_successfully) before this container starts.
verify_provisioner() {
    local ok=1
    if ! tpm2_readpublic -Q -c "0x81010001" 2>/dev/null; then
        echo "[entrypoint] ERROR: EK handle 0x81010001 not found in TPM NV." >&2
        ok=0
    fi
    if ! tpm2_readpublic -Q -c "${AK_HANDLE}" 2>/dev/null; then
        echo "[entrypoint] ERROR: AK handle ${AK_HANDLE} not found in TPM NV." >&2
        ok=0
    fi
    if [ ! -f "${CA_DIR}/ak_cert.pem" ]; then
        echo "[entrypoint] ERROR: ${CA_DIR}/ak_cert.pem not found." >&2
        ok=0
    fi
    if [ "${ok}" -eq 0 ]; then
        echo "[entrypoint] Provisioner did not complete successfully. Aborting." >&2
        exit 1
    fi
    echo "[entrypoint] Provisioner artefacts verified."
    echo "[entrypoint]   AK cert: $(openssl x509 -noout -subject -in "${CA_DIR}/ak_cert.pem")"
}

# ── Step 3: activate tpm2-openssl provider ────────────────────────────────────
# OPENSSL_CONF is needed only for key generation (Step 4).
# It is unset in a subshell for the cmpClient call (Step 5) to prevent the
# tpm2-openssl provider from opening a competing TCTI connection to mssim.
configure_openssl() {
    local cnf="${WORK_DIR}/openssl.cnf"
    cat > "${cnf}" <<EOF
openssl_conf = openssl_init

[openssl_init]
providers = provider_sect

[provider_sect]
default = default_sect
tpm2    = tpm2_sect

[default_sect]
activate = 1

[tpm2_sect]
activate = 1
tcti = ${OPENSSL_TCTI}
EOF
    export OPENSSL_CONF="${cnf}"
    echo "[entrypoint] OPENSSL_CONF=${OPENSSL_CONF}  (tcti=${OPENSSL_TCTI})"
    echo "[entrypoint] Loaded OpenSSL providers:"
    openssl list -providers
}

# ── Step 4: generate TPM-resident subject key ─────────────────────────────────
generate_tpm_key() {
    echo "[entrypoint] Generating TPM-resident RSA-2048 subject key..."

    # WHY unset OPENSSL_CONF: when OPENSSL_CONF loads both default and tpm2
    # providers, OpenSSL's algorithm dispatch selects the default provider's RSA
    # implementation (it has higher priority), producing a software PKCS8
    # "PRIVATE KEY" PEM instead of the "TSS2 PRIVATE KEY" PEM that tpm_ops.c
    # requires.  With OPENSSL_CONF unset and only the tpm2 provider on the
    # command line, the tpm2 provider wins and generates a TPM-resident key
    # whose TCTI is read from the TPM2OPENSSL_TCTI environment variable.
    #
    # SPEC §C-2: the KeyAttestPoP scheme requires the subject key to be
    # provisioned with sign+decrypt attributes and a baked-in RSA_OAEP/SHA-256
    # scheme so Esys_RSA_Decrypt succeeds.  The tpm2-openssl provider supports
    # this via the "attribs" pkeyopt (decrypt|sign userwithauth|fixedtpm|...)
    # and the "scheme:rsaoaep" pkeyopt.
    (
        unset OPENSSL_CONF
        # tpm2-openssl 1.3.0 settable pkeyopts: rsa_keygen_bits, parent,
        # parent-auth, user-auth.  The default TPM2B_PUBLIC the provider
        # generates already has TPMA_OBJECT_USERWITHAUTH | _SIGN_ENCRYPT |
        # _DECRYPT | _FIXEDTPM | _FIXEDPARENT | _SENSITIVEDATAORIGIN, and a
        # NULL scheme (caller chooses scheme at use time), which is exactly
        # what KeyAttestPoP needs — we use Esys_RSA_Decrypt with OAEP-SHA256
        # at decrypt time on a sign+decrypt-capable key.
        openssl genpkey \
            -provider tpm2 \
            -algorithm RSA \
            -pkeyopt "rsa_keygen_bits:2048" \
            -pkeyopt "parent:${SRK_HANDLE}" \
            -pkeyopt "user-auth:" \
            -out "${WORK_DIR}/tpm_key.pem"
    )

    # Export plain public key PEM: used as -newkey in cmpClient so that
    # cmpClient needs only the default provider (no TCTI opened).
    # Both providers are needed here: tpm2 decodes TSS2 PRIVATE KEY, default
    # provides the file store loader (required for -in file: URI).
    (
        unset OPENSSL_CONF
        openssl pkey \
            -provider tpm2 \
            -provider default \
            -in  "${WORK_DIR}/tpm_key.pem" \
            -pubout \
            -out "${WORK_DIR}/tpm_key.pub.pem"
    )

    echo "[entrypoint] Subject key generated (sign + decrypt, RSA_OAEP/SHA-256)."
    echo "[entrypoint] Public key info:"
    openssl pkey -in "${WORK_DIR}/tpm_key.pub.pem" -pubin -text -noout
}

# ── Step 5: CMP IR with native Esys_Certify attestation ──────────────────────
request_certificate() {
    if [ -z "${CMP_SERVER:-}" ]; then
        echo "[entrypoint] CMP_SERVER not set — skipping CMP certificate enrollment."
        return 0
    fi

    # Negative test (gate G5): CMP_BAD_ATTEST_SIG=1 corrupts the TPM2_Quote AK
    # signature inside the evidence bundle; the verifier rejects the evidence
    # and the MockCA returns PKIFailureInfo badMessageCheck on the wire.
    local bad_sig_flag=""
    if [ "${CMP_BAD_ATTEST_SIG:-0}" = "1" ]; then
        bad_sig_flag="-bad_attest_sig"
        echo "[entrypoint] WARNING: CMP_BAD_ATTEST_SIG=1 — corrupting quote AK signature (negative test)"
    fi

    # Optional wire capture: CMP_MSG_CAPTURE=1 dumps each PKIMessage the client
    # sends/receives as DER under ${OUTPUT_DIR} (genm/ir requests, genp/ip
    # responses) for offline `openssl asn1parse` inspection.
    local msg_capture_flags=""
    if [ "${CMP_MSG_CAPTURE:-0}" = "1" ]; then
        msg_capture_flags="-reqout ${OUTPUT_DIR}/req1-genm.der,${OUTPUT_DIR}/req2-ir.der -rspout ${OUTPUT_DIR}/rsp1-genp.der,${OUTPUT_DIR}/rsp2-ip.der"
        echo "[entrypoint] CMP message capture enabled → ${OUTPUT_DIR}/req*-*.der, rsp*-*.der"
    fi

    # Fetch the mock-CA root cert for use as a trust anchor.
    # The /root-cert endpoint returns base64-encoded DER; decode to PEM so
    # cmpClient can verify the signature-protected ERROR/PKIConf responses.
    # Without this, cmpClient errors with "no trust store nor pinned server cert
    # available for verifying signature-based CMP message protection" on CERTCONF.
    local mock_ca_pem="${WORK_DIR}/mock_ca.pem"
    if wget -q -O- "http://${CMP_SERVER}/root-cert" \
            | base64 -d \
            | openssl x509 -inform der -out "${mock_ca_pem}" 2>/dev/null; then
        echo "[entrypoint] Mock-CA root cert fetched: ${mock_ca_pem}"
    else
        echo "[entrypoint] WARNING: could not fetch mock-CA root cert; proceeding without -trusted"
        mock_ca_pem=""
    fi
    local trusted_flag=""
    [ -n "${mock_ca_pem}" ] && trusted_flag="-trusted ${mock_ca_pem}"

    echo "[entrypoint] Sending CMP IR to ${CMP_SERVER}${CMP_PATH:+/${CMP_PATH}}..."

    # Proof-of-possession mode.  Default 0 = raVerified: the attestation
    # evidence substitutes for a POPO signature, so cmpClient needs only the
    # subject PUBLIC key and never touches the TPM.
    #
    # CMP_POPO selects the proof-of-possession mode:
    #   0 (default) = raVerified.  The attestation evidence stands in for a
    #       POPO signature, so cmpClient needs only the subject PUBLIC key,
    #       loads no tpm2 provider, and never opens a competing TCTI (see the
    #       OPENSSL_CONF note below).  This is the path the e2e gates exercise.
    #   1 = SIGNATURE POPO (OSSL_CRMF_POPO_SIGNATURE).  cmpClient is handed the
    #       TPM-resident subject key (the TSS2 PRIVATE KEY blob) and the
    #       tpm2-openssl provider signs the CertRequest automatically — no
    #       hand-rolled signature (cf. siemens/gencmpclient PR #119, which
    #       loads `-newkey tpm2:handle=...` the same way).  The provider holds
    #       a TPM connection for the process lifetime AND tpm_ops.c needs one
    #       for the in-process quote, so both are routed through a tpm2-abrmd
    #       resource manager (tcti=tabrmd) that multiplexes the single mssim
    #       session.  On real hardware /dev/tpmrm0 does this for free.
    local popo_mode="${CMP_POPO:-0}"
    local newkey_arg="${WORK_DIR}/tpm_key.pub.pem"
    local cmp_tcti="${TCTI}"          # mssim, used by tpm_ops.c's in-process quote
    local use_provider=0              # whether cmpClient loads the tpm2 provider

    if [ "${popo_mode}" = "1" ]; then
        echo "[entrypoint] CMP_POPO=1 — signature POPO via tpm2 provider over tpm2-abrmd"
        start_resource_manager        # sets RM_TCTI=tabrmd:... and starts abrmd → mssim
        newkey_arg="${WORK_DIR}/tpm_key.pem"   # TSS2 blob: provider signs POPO with it
        cmp_tcti="${RM_TCTI}"                   # tpm_ops.c quote also via abrmd
        use_provider=1
    fi

    # Attestation statement type.  The gencmpclient native path defaults
    # -tpm_attest_type to "certify", so the type is ALWAYS passed explicitly
    # here — even for quote — to pin the platform demo's TcgAttestQuote leg.
    #   quote   (default) → TPM2_Quote   → TcgAttestQuote   (2.23.133.20.2),
    #                       request type OID = 1.2.3.4.5 and response type
    #                       OID = 1.2.3.4.6.
    #   certify           → TPM2_Certify over the TPM-resident subject key →
    #                       TcgAttestCertify (2.23.133.20.1), reqInfo type OID =
    #                       TPM_KEY_ATTEST_OID.  The verifier's G1 key-binding
    #                       check ties the certified key's TPMT_PUBLIC to the
    #                       issued cert; the evidence stands in for PoP
    #                       (raVerified), so no OAEP/PBMAC loop is run.
    local attest_type="${CMP_ATTEST_TYPE:-quote}"
    local subject_pem_flag=""
    if [ "${attest_type}" = "certify" ]; then
        # Esys_Certify must load the TPM-resident subject key, so hand cmpClient
        # the TSS2 PRIVATE KEY blob (tpm_key.pem) via -tpm_subject_pem.  -newkey
        # stays the plain public PEM: it is the subject key embedded in the CSR
        # (and, under raVerified, the only key cmpClient needs for the request).
        subject_pem_flag="-tpm_subject_pem ${WORK_DIR}/tpm_key.pem"
        echo "[entrypoint] CMP_ATTEST_TYPE=certify — TPM2_Certify over ${WORK_DIR}/tpm_key.pem (key attestation)"
    else
        echo "[entrypoint] CMP_ATTEST_TYPE=${attest_type} — TPM2_Quote (platform attestation)"
    fi

    # OPENSSL_CONF / TCTI handling for cmpClient:
    #
    # The tpm2-openssl provider's OSSL_provider_init calls
    # Tss2_TctiLdr_Initialize() eagerly and HOLDS the connection for the
    # process lifetime (init success path stores esys_ctx in provctx and never
    # finalizes; only the goto-err paths finalize).  So with the provider
    # loaded, cmpClient permanently occupies one TPM session.
    #   - popo=0: unset OPENSSL_CONF so NO provider loads; tpm_ops.c is the only
    #     TPM client and opens/closes its own mssim TCTI per call.
    #   - popo=1: keep the provider (it signs the POPO) but point both it and
    #     tpm_ops.c at tabrmd, so abrmd multiplexes the single mssim session.
    (
        if [ "${use_provider}" = "1" ]; then
            export TPM2OPENSSL_TCTI="${RM_TCTI}"   # provider → abrmd → mssim
        else
            unset OPENSSL_CONF
        fi
        # shellcheck disable=SC2086
        cmpClient \
            -config          "" \
            -cmd             ir \
            -server          "${CMP_SERVER}" \
            -path            "${CMP_PATH:-issuing}" \
            -recipient       "${CMP_RECIPIENT:-/CN=CMP-Test-Suite-CA}" \
            -subject         "${CMP_SUBJECT:-/CN=tpm-platform-attester}" \
            -newkey          "${newkey_arg}" \
            -popo            "${popo_mode}" \
            -ref             "${CMP_REF:-tpm-platform-attester}" \
            -secret          "${CMP_SECRET:-SiemensIT}" \
            -tpm_ak_handle      "${AK_HANDLE}" \
            -tpm_ak_cert        "${CA_DIR}/ak_cert.pem" \
            -tpm_tcti           "${cmp_tcti}" \
            -tpm_attest_type    "${attest_type}" \
            -implicit_confirm \
            ${subject_pem_flag} \
            ${trusted_flag} \
            ${bad_sig_flag} \
            ${msg_capture_flags} \
            -certout            "${OUTPUT_DIR}/enrolled.pem"
    )

    echo "[entrypoint] Enrolled certificate written to ${OUTPUT_DIR}/enrolled.pem"
}

# ── Step 6: publish artefacts ─────────────────────────────────────────────────
publish_artefacts() {
    echo "[entrypoint] Publishing artefacts to ${OUTPUT_DIR}/ ..."
    local work_files=(tpm_key.pem tpm_key.pub.pem openssl.cnf)
    for f in "${work_files[@]}"; do
        if [ -f "${WORK_DIR}/${f}" ]; then
            cp "${WORK_DIR}/${f}" "${OUTPUT_DIR}/${f}"
            echo "[entrypoint]   ${OUTPUT_DIR}/${f}"
        fi
    done
    local ca_files=(ca_cert.pem ak_cert.pem ak.pub.pem)
    for f in "${ca_files[@]}"; do
        if [ -f "${CA_DIR}/${f}" ]; then
            cp "${CA_DIR}/${f}" "${OUTPUT_DIR}/${f}"
            echo "[entrypoint]   ${OUTPUT_DIR}/${f}"
        fi
    done
}

# ── Summary ───────────────────────────────────────────────────────────────────
print_summary() {
    echo ""
    echo "=== TPM Platform Attestation Complete ==="
    printf '  %-32s %s\n' "TPM key (TSS2 PEM handle):" "${OUTPUT_DIR}/tpm_key.pem"
    printf '  %-32s %s\n' "TPM public key:"            "${OUTPUT_DIR}/tpm_key.pub.pem"
    printf '  %-32s %s\n' "CA certificate:"            "${OUTPUT_DIR}/ca_cert.pem"
    printf '  %-32s %s\n' "AK certificate:"            "${OUTPUT_DIR}/ak_cert.pem"
    if [ -f "${OUTPUT_DIR}/enrolled.pem" ]; then
        printf '  %-32s %s\n' "Enrolled certificate:" "${OUTPUT_DIR}/enrolled.pem"
    fi
    echo ""
    echo "[entrypoint] All artefacts written to ${OUTPUT_DIR}/"
}

# Copy-paste-ready box showing how to interact with this attester container.
# Shared by the startup banner (below) and request-certificate.bash, which sources
# this file — so the box stays identical in both places.
print_interaction_box() {
    printf '\n'
    printf '############################################################################################\n'
    printf '# Interact with this attester container:\n'
    printf '#   Log in:   docker exec -it attestation-attester-tpm-platform-attester-1 bash\n'
    printf '#   Re-enrol: docker exec -it attestation-attester-tpm-platform-attester-1 \\\n'
    printf '#             /app/request-certificate.bash\n'
    printf '############################################################################################\n'
}

# Banner printed by the entrypoint once the TPM is provisioned and the attester
# is idling — enrolment is on-demand (see request-certificate.bash).
print_ready_banner() {
    echo ""
    echo "=== TPM attester ready ==="
    echo "[entrypoint] Provisioner artefacts verified; TPM up; subject key generated on demand."
    print_interaction_box
    echo "[entrypoint] Container staying alive (exec sleep infinity)."
    echo ""
}

# ── Main ──────────────────────────────────────────────────────────────────────
# When run as the container entrypoint: provision-verify + idle (the certificate
# enrolment is on demand via request-certificate.bash, which `source`s this file
# for the shared helpers).  When this file is sourced, only the functions load —
# the guard below keeps the entrypoint flow from re-running.
if [ "${BASH_SOURCE[0]}" = "${0}" ]; then
    tpm_startup
    verify_provisioner
    publish_artefacts
    print_ready_banner
    exec sleep infinity
fi
