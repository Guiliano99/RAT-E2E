#!/usr/bin/env bash
# provision.sh — One-time SRK/EK/AK provisioning for TPM 2.0
#
# Creates persistent handles:
#   SRK (RSA-2048, owner-hierarchy primary)     → 0x81000001
#   EK  (RSA-2048, endorsement key)             → 0x81010001
#   AK  (RSA-SHA256-RSASSA, attest key)         → 0x81010002
#
# The SRK is required as the parent for the TPM-resident subject key generated
# at enrollment time (`openssl genpkey -provider tpm2 -pkeyopt parent:0x81000001`).
# tpm2-openssl's default parent (TPM_RH_OWNER hierarchy handle 0x40000001) is
# rejected by Esys_TR_FromTPMPublic in tpm_ops.c, so a persistent object handle
# is needed.
#
# Generates and writes to /tpm-ca (shared Docker volume):
#   ca_key.pem    — local CA private key (signs the AK cert)
#   ca_cert.pem   — self-signed CA cert  (trusted by tpm-verifier)
#   ak.pub.pem    — AK RSA public key    (for out-of-band inspection)
#   ak_cert.pem   — AK X.509 cert signed by ca_key.pem
#
# Idempotent: exits 0 immediately if all three handles are already persisted
# and /tpm-ca/ak_cert.pem already exists.
#
# Environment:
#   TPM2TOOLS_TCTI  — TCTI string (e.g. "mssim:host=simulator,port=2321")
#                     or "device:/dev/tpmrm0" for a real TPM.
set -euo pipefail

SRK_HANDLE="0x81000001"
EK_HANDLE="0x81010001"
AK_HANDLE="0x81010002"
TCTI="${TPM2TOOLS_TCTI:-mssim:host=simulator,port=2321}"
export TPM2TOOLS_TCTI="${TCTI}"

CA_DIR="/tpm-ca"
WORK_DIR="/tmp/provision"
mkdir -p "${CA_DIR}" "${WORK_DIR}"

# PROVISION_MODE controls idempotency behaviour:
#   static (default) — skip all steps if handles and AK cert are already present.
#   fresh            — evict any existing handles and re-provision from scratch.
#                      Use when a clean key set is required at every run.
PROVISION_MODE="${PROVISION_MODE:-static}"

# ── Step 1: wait for simulator / real TPM ─────────────────────────────────────
echo "[provision] Waiting for TPM startup..."
retries=40
while [ "${retries}" -gt 0 ]; do
    if tpm2_startup -c 2>/dev/null; then
        echo "[provision] TPM2_Startup(CLEAR) succeeded"
        break
    fi
    sleep 1
    retries=$(( retries - 1 ))
done
if [ "${retries}" -eq 0 ]; then
    echo "[provision] ERROR: TPM did not become ready after 40 s" >&2
    exit 1
fi

# ── Step 2: idempotency / fresh-mode gate ─────────────────────────────────────
if [ "${PROVISION_MODE}" = "fresh" ]; then
    echo "[provision] PROVISION_MODE=fresh — evicting existing handles before re-provisioning..."
    tpm2_evictcontrol -C o -c "${AK_HANDLE}"  2>/dev/null || true
    tpm2_evictcontrol -C o -c "${EK_HANDLE}"  2>/dev/null || true
    tpm2_evictcontrol -C o -c "${SRK_HANDLE}" 2>/dev/null || true
    tpm2_flushcontext -t 2>/dev/null || true
    tpm2_flushcontext -s 2>/dev/null || true
    rm -f "${CA_DIR}/ak_cert.pem" "${CA_DIR}/ca_cert.pem" \
          "${CA_DIR}/ak.pub.pem"  "${CA_DIR}/pcr_reference.json"
    echo "[provision] Existing handles and artefacts cleared; provisioning fresh keys."
else
    # static mode: if all three handles exist AND the AK cert is present, skip.
    if tpm2_readpublic -Q -c "${SRK_HANDLE}" 2>/dev/null \
       && tpm2_readpublic -Q -c "${EK_HANDLE}" 2>/dev/null \
       && tpm2_readpublic -Q -c "${AK_HANDLE}" 2>/dev/null \
       && [ -f "${CA_DIR}/ak_cert.pem" ]; then
        echo "[provision] Handles ${SRK_HANDLE}/${EK_HANDLE}/${AK_HANDLE} already provisioned; nothing to do."
        exit 0
    fi
fi

# ── Step 3: create SRK at 0x81000001 ─────────────────────────────────────────
echo "[provision] Creating SRK (RSA-2048, owner hierarchy primary)..."
tpm2_createprimary -C o -c "${WORK_DIR}/srk.ctx"
tpm2_evictcontrol -C o -c "${SRK_HANDLE}" 2>/dev/null || true
tpm2_evictcontrol -C o -c "${WORK_DIR}/srk.ctx" "${SRK_HANDLE}"
echo "[provision] SRK persisted at ${SRK_HANDLE}"
tpm2_flushcontext -t 2>/dev/null || true
tpm2_flushcontext -s 2>/dev/null || true

# ── Step 4: create EK at 0x81010001 ──────────────────────────────────────────
echo "[provision] Creating EK (RSA-2048)..."
tpm2_createek \
    -c "${WORK_DIR}/ek.ctx" \
    -G rsa \
    -u "${WORK_DIR}/ek.pub"

# Evict any stale object at the handle before persisting.
tpm2_evictcontrol -C o -c "${EK_HANDLE}" 2>/dev/null || true

tpm2_evictcontrol -C o -c "${WORK_DIR}/ek.ctx" "${EK_HANDLE}"
echo "[provision] EK persisted at ${EK_HANDLE}"

# tpm2_evictcontrol persists the object but does NOT free the transient slot
# (TPM2 spec Part 3 §28.3.5.2).  tpm2_createek also leaves policy sessions open.
# Flush everything before tpm2_createak or the simulator runs out of object memory.
tpm2_flushcontext -t 2>/dev/null || true
tpm2_flushcontext -s 2>/dev/null || true

# ── Step 5: create AK at 0x81010002 ──────────────────────────────────────────
echo "[provision] Creating AK (RSA-SHA256-RSASSA)..."
tpm2_createak \
    -C "${WORK_DIR}/ek.ctx" \
    -c "${WORK_DIR}/ak.ctx" \
    -u "${WORK_DIR}/ak.pub" \
    -n "${WORK_DIR}/ak.name" \
    -r "${WORK_DIR}/ak.priv" \
    -G rsa -g sha256 -s rsassa

# Flush transient objects (mssim transient-object limit).
tpm2_flushcontext -t 2>/dev/null || true

tpm2_evictcontrol -C o -c "${AK_HANDLE}" 2>/dev/null || true
tpm2_evictcontrol -C o -c "${WORK_DIR}/ak.ctx" "${AK_HANDLE}"
echo "[provision] AK persisted at ${AK_HANDLE}"

tpm2_flushcontext -t 2>/dev/null || true

# ── Step 6: read AK public key in PEM ────────────────────────────────────────
echo "[provision] Reading AK public key..."
tpm2_readpublic -c "${AK_HANDLE}" -f pem -o "${CA_DIR}/ak.pub.pem"

tpm2_flushcontext -t 2>/dev/null || true

# ── Step 7: generate CA key + self-signed cert ───────────────────────────────
echo "[provision] Generating local CA key and certificate..."
openssl genpkey \
    -algorithm RSA \
    -pkeyopt rsa_keygen_bits:2048 \
    -out "${WORK_DIR}/ca_key.pem"
openssl req -new -x509 \
    -key "${WORK_DIR}/ca_key.pem" \
    -out "${CA_DIR}/ca_cert.pem" \
    -days 3650 \
    -subj "/CN=TPM AK CA (PoC)/O=PoC Org/C=DE" \
    -addext "basicConstraints=critical,CA:TRUE" \
    -addext "keyUsage=critical,keyCertSign,cRLSign"
echo "[provision] CA certificate written to ${CA_DIR}/ca_cert.pem"

# ── Step 8: generate AK certificate signed by the local CA ───────────────────
# We have only the AK public key; generate a throwaway key to produce a CSR,
# then use -force_pubkey to replace it with the real AK public key.
echo "[provision] Generating AK certificate..."

openssl genpkey \
    -algorithm RSA \
    -pkeyopt rsa_keygen_bits:2048 \
    -out "${WORK_DIR}/tmp_key.pem"

openssl req -new \
    -key "${WORK_DIR}/tmp_key.pem" \
    -subj "/CN=TPM AK/O=PoC Org/C=DE" \
    -out "${WORK_DIR}/ak.csr"

openssl x509 -req \
    -in "${WORK_DIR}/ak.csr" \
    -CA "${CA_DIR}/ca_cert.pem" \
    -CAkey "${WORK_DIR}/ca_key.pem" \
    -CAcreateserial \
    -force_pubkey "${CA_DIR}/ak.pub.pem" \
    -out "${CA_DIR}/ak_cert.pem" \
    -days 3650

rm -f "${WORK_DIR}/tmp_key.pem" "${WORK_DIR}/ak.csr"
echo "[provision] AK certificate written to ${CA_DIR}/ak_cert.pem"

# ── Step 9: capture PCR reference values ─────────────────────────────────────
# Read the current SHA-256 PCR bank (PCRs 0-4) and compute the expected
# pcrDigest = SHA-256( PCR0 || PCR1 || ... || PCR4 ) so the tpm-verifier can
# enforce platform integrity when quote attestation (TcgAttestQuote) is used.
#
# These values reflect the post-provisioning platform state.  On the TCG
# simulator all PCRs start at 0x000...0 (CLEAR startup) and provision.sh does
# not extend any PCRs, so the digest is deterministic across simulator runs.
# On real hardware, re-run provision.sh after each firmware update to re-baseline.
echo "[provision] Capturing PCR reference values (sha256:0-4)..."
tpm2_pcrread sha256:0,1,2,3,4 -o "${WORK_DIR}/pcr_values.bin"
tpm2_flushcontext -t 2>/dev/null || true

pcr_digest_hex=$(openssl dgst -sha256 -hex "${WORK_DIR}/pcr_values.bin" | awk '{print $2}')
cat > "${CA_DIR}/pcr_reference.json" <<JSON
{
  "description": "Golden boot state — post-provisioning SHA-256 PCRs 0-4",
  "expected_pcr_digest_hex": "${pcr_digest_hex}"
}
JSON
echo "[provision] PCR reference written to ${CA_DIR}/pcr_reference.json (digest=${pcr_digest_hex})"

# ── Summary ───────────────────────────────────────────────────────────────────
echo ""
echo "=== TPM Provisioning Complete ==="
printf '  %-25s %s\n' "SRK handle:"     "${SRK_HANDLE}"
printf '  %-25s %s\n' "EK handle:"      "${EK_HANDLE}"
printf '  %-25s %s\n' "AK handle:"      "${AK_HANDLE}"
printf '  %-25s %s\n' "AK public key:"  "${CA_DIR}/ak.pub.pem"
printf '  %-25s %s\n' "CA cert:"        "${CA_DIR}/ca_cert.pem"
printf '  %-25s %s\n' "AK cert:"        "${CA_DIR}/ak_cert.pem"
printf '  %-25s %s\n' "PCR reference:"  "${CA_DIR}/pcr_reference.json"
echo ""
