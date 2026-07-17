#!/usr/bin/env bash
# Verifier entrypoint — selects the AK-chain trust anchor at container start.
#
# Positive (default, ATTEST_NEG=0): leave TRUSTED_CA_CERT_FILE as provided by the
# compose environment (/tpm-ca/ca_cert.pem — the live CA the attester's provisioner
# wrote to the shared volume, the same CA that signed the AK cert → chain validates).
#
# Negative (ATTEST_NEG=1, baked in by `NEG=1 docker compose build`): point the trust
# anchor at the static foreign-manufacturer CA instead.  The AK cert is signed by the
# provisioner CA, so validate_ek_chain() in tpm_verifier.py rejects it → contraindicated
# → MockCA refuses the certificate (PKIFailureInfo: badMessageCheck).  This demonstrates
# rejecting a TPM whose manufacturer is not a trusted/known one.
set -euo pipefail

if [ "${ATTEST_NEG:-0}" = "1" ]; then
    echo "[verifier] NEG build: trusting WRONG (foreign-manufacturer) CA — enrolment must be refused"
    export TRUSTED_CA_CERT_FILE=/opt/tpm-verifier/config/wrong_ca_cert.pem
fi

exec "$@"
