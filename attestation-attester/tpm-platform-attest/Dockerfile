# ── Attester build ─────────────────────────────────────────────────────────────
# Every dependency is cloned from a published branch — no local vendoring, so the
# image builds from exactly what a fresh clone gets. Clones cache like any other
# layer: pass --no-cache to force a fresh pull of a branch tip.
ARG OPENSSL_REPO=https://github.com/Guiliano99/openssl.git
ARG OPENSSL_BRANCH=demo/docker_RATS2_OLD_V9
ARG GENCMPCLIENT_REPO=https://github.com/Guiliano99/gencmpclient.git
ARG GENCMPCLIENT_BRANCH=demo/docker_RATS2_TPMV4_COSE
ARG LIBATTEST_REPO=https://github.com/Guiliano99/libattest-py.git
# Keep LIBATTEST_BRANCH aligned with the MockCA and verifier Dockerfiles.
ARG LIBATTEST_BRANCH=UpdateV8_1

# ── Source stages ──────────────────────────────────────────────────────────────
FROM ubuntu:24.04 AS src-openssl
ARG OPENSSL_REPO
ARG OPENSSL_BRANCH
RUN apt-get update && apt-get install -y --no-install-recommends git ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    && git clone --depth 1 --branch "${OPENSSL_BRANCH}" "${OPENSSL_REPO}" /src \
    && rm -rf /src/.git

FROM ubuntu:24.04 AS src-gencmp
ARG GENCMPCLIENT_REPO
ARG GENCMPCLIENT_BRANCH
RUN apt-get update && apt-get install -y --no-install-recommends git ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    && git clone --depth 1 --branch "${GENCMPCLIENT_BRANCH}" \
           "${GENCMPCLIENT_REPO}" /src \
    && cd /src && git submodule update --init libsecutils \
    && rm -rf /src/.git /src/libsecutils/.git

FROM ubuntu:24.04 AS src-libattest
ARG LIBATTEST_REPO
ARG LIBATTEST_BRANCH
RUN apt-get update && apt-get install -y --no-install-recommends git ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    && git clone --depth 1 --branch "${LIBATTEST_BRANCH}" "${LIBATTEST_REPO}" /tmp/libattest \
    && mkdir -p /src \
    && cp /tmp/libattest/pyproject.toml /tmp/libattest/README.md /src/ \
    && cp -r /tmp/libattest/src /src/src \
    && rm -rf /tmp/libattest

# ── Build stage ────────────────────────────────────────────────────────────────
FROM ubuntu:24.04

ARG TPM2_TSS_VERSION=4.1.3
ARG TPM2_TOOLS_VERSION=5.7
ARG OPENSSL_PREFIX=/usr/local/openssl

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential git make gcc g++ wget perl ca-certificates \
    automake autoconf autoconf-archive libtool libltdl-dev pkg-config cmake \
    libjson-c-dev libcjson-dev libglib2.0-dev libtasn1-6-dev uuid-dev \
    libcurl4-openssl-dev \
    dbus libdbus-1-dev \
    python3-dev python3-pip \
    && rm -rf /var/lib/apt/lists/*

# cmpClient embeds Python; fail early if its interpreter and headers do not match.
RUN PY_INC="$(python3 -c 'import sysconfig; print(sysconfig.get_path("include"))')" \
    && test -f "${PY_INC}/Python.h" || { \
        echo "FATAL: python3 reports include dir ${PY_INC} but it has no" \
             "Python.h ($(python3 --version) vs. installed dev headers)." >&2; \
        exit 1; \
    }

# ── OpenSSL ────────────────────────────────────────────────────────────────────
# The fork installs to ${OPENSSL_PREFIX} and every component below links against
# it — which is why tpm2-tss is built from source here rather than taken from apt.
COPY --from=src-openssl /src /root/openssl
WORKDIR /root/openssl
RUN make distclean >/dev/null 2>&1 || true
# The EAR extension printer needs libcrypto linked with cJSON; verify that link.
RUN ./config --banner=Configured --strict-warnings shared \
        --prefix="${OPENSSL_PREFIX}" --openssldir="${OPENSSL_PREFIX}" \
        -lcjson && \
    make -j"$(nproc)" -s && \
    make install_sw install_ssldirs && \
    ldd "${OPENSSL_PREFIX}/lib64/libcrypto.so.3" | grep -q cjson

ENV PKG_CONFIG_PATH="${OPENSSL_PREFIX}/lib64/pkgconfig:${OPENSSL_PREFIX}/lib/pkgconfig:/usr/local/lib/pkgconfig:/usr/local/lib64/pkgconfig"
ENV LD_LIBRARY_PATH="${OPENSSL_PREFIX}/lib64:${OPENSSL_PREFIX}/lib:/usr/local/lib:/usr/local/lib64"
ENV PATH="${OPENSSL_PREFIX}/bin:${PATH}"

# ── tpm2-tss ───────────────────────────────────────────────────────────────────
# Built before tpm2-openssl, which needs tss2-esys. --with-crypto=ossl links the
# fork; --disable-fapi avoids ASN1 APIs incompatible with OpenSSL 4.
WORKDIR /root
RUN git clone --depth 1 --branch "${TPM2_TSS_VERSION}" \
        https://github.com/tpm2-software/tpm2-tss.git
WORKDIR /root/tpm2-tss
RUN git submodule update --init && \
    ./bootstrap && \
    ./configure \
        --disable-doxygen-doc \
        --disable-fapi \
        --with-crypto=ossl \
    && make -j"$(nproc)" && make install && ldconfig

# ── tpm2-abrmd ─────────────────────────────────────────────────────────────────
# Required only for CMP_POPO=1, which needs concurrent TPM access for signature PoP.
WORKDIR /root
RUN git clone --depth 1 --branch 3.0.0 \
        https://github.com/tpm2-software/tpm2-abrmd.git
WORKDIR /root/tpm2-abrmd
RUN ./bootstrap && \
    ./configure --with-dbuspolicydir=/usr/share/dbus-1/system.d \
    && make -j"$(nproc)" && make install && ldconfig

# ── tpm2-openssl ───────────────────────────────────────────────────────────────
# The TPM2 provider behind `openssl genpkey -provider tpm2`, used only to generate
# the TPM-resident subject key.
WORKDIR /root
RUN git clone --depth 1 --branch 1.3.0 \
        https://github.com/tpm2-software/tpm2-openssl.git
WORKDIR /root/tpm2-openssl
RUN ./bootstrap && \
    ./configure \
        --with-openssl="${OPENSSL_PREFIX}" \
    && make -j"$(nproc)" && make install && ldconfig

# ── gencmpclient ───────────────────────────────────────────────────────────────
# Evidence generation lives in libattest-py, not here: cmpClient embeds CPython
# and calls libattest.attester.evidence_bridge (src/tpm_py_bridge.c); tpm_ops.c
# and its TSS2 ESYS linkage are gone, so quote/certify formats change in Python
# with no C rebuild of this fork.
ARG GENCMP_CFLAGS="-DOPENSSL_API_COMPAT=0x30200000L -Wno-error=unused-parameter -D_OPENSSL_VERSION_PRE_RELEASE=0"

COPY --from=src-gencmp /src /root/gencmpclient
WORKDIR /root/gencmpclient

RUN NDEBUG=1 \
    OPENSSL_DIR="${OPENSSL_PREFIX}" \
    OPENSSL_LIB="${OPENSSL_PREFIX}/lib64" \
    CFLAGS="${GENCMP_CFLAGS}" \
    make -C libsecutils -f Makefile_v1 build_all -s

# gencmpclient's link step expects libsecutils.so* in the source root.
RUN ln -sf libsecutils/libsecutils.so* .

# build_only skips OpenSSL_version.c (a version-check tool, not runtime code).
RUN NDEBUG=1 \
    OPENSSL_DIR="${OPENSSL_PREFIX}" \
    OPENSSL_LIB="${OPENSSL_PREFIX}/lib64" \
    LD_LIBRARY_PATH="${OPENSSL_PREFIX}/lib64" \
    CFLAGS="${GENCMP_CFLAGS}" \
    make -f Makefile_v1 build_only -s

RUN install -m 755 cmpClient /usr/local/bin/ && \
    install -m 644 libgencmp.so* /usr/local/lib/ && \
    install -m 644 libsecutils/libsecutils.so* /usr/local/lib/ && \
    ldconfig

# ── libattest-py ───────────────────────────────────────────────────────────────
# Install the [tpm] extra's dependencies (notably tpm2-pytss, a CFFI extension the
# quote path needs), then uninstall the package itself so the PYTHONPATH source
# tree below wins over site-packages. --ignore-requires-python: this base is
# Python 3.12 against libattest's declared floor of >=3.13; the import check below
# gates the build rather than letting it fail inside the embedded interpreter.
RUN --mount=type=bind,from=src-libattest,source=/src,target=/mnt/libattest-src,rw \
    pip install --break-system-packages --no-cache-dir --ignore-requires-python \
        "/mnt/libattest-src[tpm]" \
    && pip uninstall --break-system-packages -y libattest-py
COPY --from=src-libattest /src/src/libattest /opt/libattest/src/libattest
ENV PYTHONPATH=/opt/libattest/src
# Ensure cmpClient's embedded evidence bridge imports with the image's Python.
RUN python3 -c "import libattest.attester.evidence_bridge as b; b.generate_tpm_evidence; print('evidence bridge import OK on', __import__('sys').version)"

# ── tpm2-tools ─────────────────────────────────────────────────────────────────
# Provisioning helpers (tpm2_createek / tpm2_createak / …) used by provision.sh.
WORKDIR /root
RUN git clone --depth 1 --branch "${TPM2_TOOLS_VERSION}" \
        https://github.com/tpm2-software/tpm2-tools.git
WORKDIR /root/tpm2-tools
RUN git submodule update --init && \
    ./bootstrap && \
    ./configure \
    && make -j"$(nproc)" && make install && ldconfig

# ── Entrypoint ─────────────────────────────────────────────────────────────────
WORKDIR /app
COPY attestation-attester/tpm-platform-attest/provision.sh \
     attestation-attester/tpm-platform-attest/entrypoint.sh \
     attestation-attester/tpm-platform-attest/request-certificate.bash \
     attestation-attester/tpm-platform-attest/e2e-enroll.sh \
     attestation-attester/tpm-platform-attest/pretty_print_stmt.py ./
RUN chmod +x provision.sh entrypoint.sh request-certificate.bash e2e-enroll.sh

ENTRYPOINT ["/app/entrypoint.sh"]
