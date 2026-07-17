# ── Source stage ───────────────────────────────────────────────────────────────
# Keep LIBATTEST_BRANCH aligned with the attester and verifier Dockerfiles.
ARG LIBATTEST_BRANCH=UpdateV8_1
FROM ghcr.io/siemens/cmp-test-base:latest AS src
ARG LIBATTEST_BRANCH
RUN apt-get update && apt-get install -y --no-install-recommends git \
    && rm -rf /var/lib/apt/lists/*
RUN git clone --depth 1 --branch AddInitRemoteAttestation \
        https://github.com/Guiliano99/cmp-test-suite-update-code.git /src \
    && rm -rf /src/.git
RUN git clone --depth 1 --branch "${LIBATTEST_BRANCH}" \
        https://github.com/Guiliano99/libattest-py.git /libattest-py \
    && rm -rf /libattest-py/.git

# ── Runtime stage ──────────────────────────────────────────────────────────────
FROM ghcr.io/siemens/cmp-test-base:latest

# Git is needed while uv resolves libattest's Git-based dependencies.
RUN apt-get update && apt-get install -y --no-install-recommends \
        git \
    && rm -rf /var/lib/apt/lists/*

# Replace the base image's default application with the remote MockCA source.
RUN rm -rf /app/*
WORKDIR /app

# libattest is the same library the attester generates evidence with; the RA/CA
# uses it to decode that evidence, so one branch covers both ends and wire
# formats change in Python only.
# /app is the runtime import path; /opt provides package metadata to uv.
COPY --from=src /src /app
COPY --from=src /libattest-py/src/libattest /app/libattest
COPY --from=src /libattest-py/pyproject.toml /libattest-py/README.md /opt/libattest/
COPY --from=src /libattest-py/src/ /opt/libattest/src/

# Fail the build if the runtime import graph is incomplete.
RUN uv pip install --python /opt/venv/bin/python3 \
        robotframework /opt/libattest \
    && PYTHONPATH=/app /opt/venv/bin/python3 -c 'import libattest.formats.cmw'

ENV PYTHONPATH=/app

ENTRYPOINT ["scripts/docker_entrypoint.py"]
CMD ["--mockca", "5000"]
