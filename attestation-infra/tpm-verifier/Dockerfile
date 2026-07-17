# ── Verifier image ──────────────────────────────────────────────────────────────
# Keep LIBATTEST_BRANCH aligned with the attester and MockCA Dockerfiles.
ARG LIBATTEST_BRANCH=UpdateV8_1

FROM python:3.13-slim
ARG LIBATTEST_BRANCH

# ── Dependencies ───────────────────────────────────────────────────────────────
# tpm2-pytss builds a native extension against the TSS2 headers.
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        libtss2-dev gcc pkg-config python3-dev libffi-dev git \
    && rm -rf /var/lib/apt/lists/*

# ── libattest ──────────────────────────────────────────────────────────────────
# The same library the attester generates evidence with — here it appraises that
# evidence, so both sides track one branch and formats change in Python only.
# [tpm] pulls tpm2-pytss for signature checks and TPMT_SIGNATURE / TPMT_PUBLIC
# unmarshalling; [verifier-service] pulls the HTTP layer. Deps resolve from
# libattest's own pyproject.toml, so no second pin list can go stale.
RUN git clone --depth 1 --branch "${LIBATTEST_BRANCH}" \
        https://github.com/Guiliano99/libattest-py.git /opt/libattest \
    && rm -rf /opt/libattest/.git \
    && pip install --no-cache-dir "/opt/libattest[tpm,verifier-service]" \
    && rm -rf /opt/libattest

# ── Application ────────────────────────────────────────────────────────────────
COPY attestation-infra/tpm-verifier/src/ /app/

# Two static trust anchors for the negative demo: correct_ca_cert.pem is the
# expected-manufacturer profile; wrong_ca_cert.pem is a different, valid CA that
# the entrypoint installs as the trust anchor when NEG=1, so the AK chain fails.
COPY attestation-infra/tpm-verifier/config/ /opt/tpm-verifier/config/

# NEG selects the static wrong-CA trust anchor for the negative demo profile.
ARG NEG=0
ENV ATTEST_NEG=${NEG}

COPY attestation-infra/tpm-verifier/entrypoint.sh /usr/local/bin/verifier-entrypoint.sh
RUN chmod +x /usr/local/bin/verifier-entrypoint.sh

ENV PYTHONPATH=/app \
    PYTHONUNBUFFERED=1

WORKDIR /app
ENTRYPOINT ["/usr/local/bin/verifier-entrypoint.sh"]
CMD ["python3", "verifier_service.py"]
