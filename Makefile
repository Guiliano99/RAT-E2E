# Makefile for the TPM platform-attestation (quote) demo.
#
# Two independent Docker Compose projects — attester (end entity + TPM) and
# infra (Verifier + RA/CA) — connected over external Docker networks and a
# shared `tpm-ca` volume (created by `make setup`). Run each project in its
# own console; start order does not matter, since the Verifier re-reads the
# trust-anchor CA on every appraisal.

.PHONY: help setup \
        start-attestation-infra start-attestation-infra-neg \
        start-attestation-attester \
        certificate test-submit test-submit-neg \
        docker-down docker-images-clean docker-clean-all \
        docker-build-no-cache docker-fresh-e2e docker-status \
        tests e2e-neg-ca-test start neg-start \
        start-infra start-attester request-certificate stop clean test-e2e e2e-pos-test

ATT := attestation-attester/docker-compose.yml
INF := attestation-infra/docker-compose.yml
DCA := docker compose -f $(ATT)
DCI := docker compose -f $(INF)
ATTESTER_SVC := tpm-platform-attester
ENROLLED := attestation-attester/tpm-platform-attest/output/enrolled.pem
TPM_VERIFIER_TEST_IMAGE := remote-attest-e2e/tpm-verifier-tests:local

# Bare `make` lists the targets rather than silently running `setup`.
.DEFAULT_GOAL := help

# ── Core targets ─────────────────────────────────────────────────────────────

help:
	@echo "TPMPCRDemo — available targets:"
	@echo "  setup                       create networks/bridges + tpm-ca volume (idempotent)"
	@echo "  start-attestation-infra     build+run verifier + MockCA (log-following)"
	@echo "  start-attestation-attester  build+run simulator + provisioner + attester"
	@echo "  certificate                 interactive guided enrolment (make certificate)"
	@echo "  test-submit / test-submit-neg  positive / negative e2e gate (stack must be up)"
	@echo "  docker-down                 stop both projects (volumes preserved)"
	@echo "  docker-images-clean / docker-clean-all  remove images / deep clean"
	@echo "  docker-build-no-cache / docker-fresh-e2e / docker-status  helpers"
	@echo "  start / neg-start / e2e-neg-ca-test  PCR bring-up + wrong-CA helpers"

# Creates the demo's Docker networks and the shared tpm-ca volume. Safe to
# re-run (`|| true` swallows the benign "already exists" error).
setup:
	./scripts/configure-network.bash || true

# Verifier + MockCA, in the foreground (log-following).
start-attestation-infra:
	cd attestation-infra && docker compose up --build

# Same as above, but built with NEG=1 to trust the wrong CA — pairs with
# `make start-attestation-attester` + `make e2e-neg-ca-test`.
start-attestation-infra-neg:
	cd attestation-infra && NEG=1 docker compose up --build

# TPM simulator + one-time provisioner + attester, in the foreground.
start-attestation-attester:
	cd attestation-attester && docker compose up --build

# Interactive guided enrolment walkthrough. Requires both projects up.
certificate:
	$(DCA) exec $(ATTESTER_SVC) /app/request-certificate.bash

# Non-interactive enrolment; asserts a certificate was issued.
test-submit:
	@rm -f $(ENROLLED)
	$(DCA) exec -T $(ATTESTER_SVC) /app/e2e-enroll.sh
	@if [ -s $(ENROLLED) ]; then \
		echo "OK: certificate issued ($(ENROLLED))"; \
	else \
		echo "FAIL: no certificate written"; exit 1; \
	fi

# Enrols with a corrupted AK signature (CMP_BAD_ATTEST_SIG=1) and asserts the
# CA refuses to issue.
test-submit-neg:
	@$(DCA) exec -T $(ATTESTER_SVC) true 2>/dev/null || { echo "FAIL: attester container not running — bring the stack up first (make start-attestation-attester); a down stack must not read as 'refused'"; exit 1; }
	@rm -f $(ENROLLED)
	@echo "=== Negative test: enrol with a corrupted AK signature (CMP_BAD_ATTEST_SIG=1) ==="
	@if $(DCA) exec -T -e CMP_BAD_ATTEST_SIG=1 $(ATTESTER_SVC) /app/e2e-enroll.sh; then \
		echo "FAIL: enrolment succeeded despite a bad AK signature"; exit 1; \
	elif [ -f $(ENROLLED) ]; then \
		echo "FAIL: a certificate was written despite the verifier's refusal"; exit 1; \
	else \
		echo "OK: bad-signature enrolment refused; no certificate written"; \
	fi

# Stops both projects. Volumes are preserved, so the provisioned EK/AK/CA
# survive a down/up cycle. Use docker-clean-all to remove them too.
docker-down:
	@echo "Stopping/removing both Compose projects (tpm-ca volume preserved)..."
	$(DCI) down --remove-orphans
	$(DCA) down --remove-orphans

docker-images-clean: docker-down
	@echo "Removing demo images..."
	$(DCI) down --rmi all --remove-orphans
	$(DCA) down --rmi all --remove-orphans
	@echo "Removing dangling Docker images..."
	@docker image prune -f

# Deep clean: images + build cache + the shared tpm-ca volume + the demo bridges.
docker-clean-all: docker-images-clean
	@echo "Removing Docker build cache..."
	@docker builder prune -af
	@echo "Removing shared tpm-ca volume and demo networks..."
	./scripts/cleanup-network.bash || true

# ── Optional supporting helpers ──────────────────────────────────────────────

docker-build-no-cache:
	@echo "Building both projects' images from scratch (--no-cache), infra first..."
	$(DCI) build --no-cache
	$(DCA) build --no-cache

# Full clean-build gate: brings both projects up and runs the positive and
# negative (corrupted AK signature) enrolments with assertions.
docker-fresh-e2e:
	cd attestation-attester/tpm-platform-attest && ./e2e-test.sh --build

docker-status:
	@echo "Demo containers:"
	@docker ps -a --format '{{.Names}}\t{{.Image}}\t{{.Status}}' | grep -E 'attestation-(infra|attester)' || true
	@echo ""
	@echo "Demo images:"
	@docker images --format '{{.Repository}}:{{.Tag}}\t{{.ID}}\t{{.Size}}' | grep -E 'attestation-(infra|attester)|tpm-verifier' || true

# ── PCR-specific helpers ──────────────────────────────────────────────────────

# Verifier unit tests, run inside its Docker image (no host Python deps needed).
tests:
	docker build -f attestation-infra/tpm-verifier/Dockerfile \
	             -t $(TPM_VERIFIER_TEST_IMAGE) .
	docker run --rm \
		-v "$(CURDIR)/attestation-infra/tpm-verifier/src:/workspace/attestation-infra/tpm-verifier/src:ro" \
		-v "$(CURDIR)/attestation-infra/tpm-verifier/tests:/workspace/attestation-infra/tpm-verifier/tests:ro" \
		-v "$(CURDIR)/attestation-infra/tpm-verifier/config:/workspace/attestation-infra/tpm-verifier/config:ro" \
		-w /workspace \
		$(TPM_VERIFIER_TEST_IMAGE) \
		python3 -m unittest discover -s attestation-infra/tpm-verifier/tests/ -p "test_*.py"

# Wrong-CA negative gate. Requires the infra built with NEG=1
# (make start-attestation-infra-neg).
e2e-neg-ca-test:
	@echo "Run the negative wrong-CA example: the verifier trusts a foreign-manufacturer"
	@echo "CA, so the attester's AK chain fails validation and no certificate is issued."
	@echo "(Requires the infra built/up with NEG=1, e.g. 'make start-attestation-infra-neg'.)"
	@$(DCA) exec -T $(ATTESTER_SVC) true 2>/dev/null || { echo "FAIL: attester container not running — bring the stack up first; a down stack must not read as 'refused'"; exit 1; }
	@rm -f $(ENROLLED)
	@if $(DCA) exec -T $(ATTESTER_SVC) /app/e2e-enroll.sh; then \
		echo "FAIL: enrolment unexpectedly succeeded (expected refusal)"; exit 1; \
	elif [ -f $(ENROLLED) ]; then \
		echo "FAIL: a certificate was written despite the verifier's refusal"; exit 1; \
	else \
		echo "OK: enrolment refused (unknown-manufacturer / wrong CA); no certificate written"; \
	fi

# Brings both projects up detached. Enrol with `make certificate` (interactive)
# or `make test-submit` (gate).
start: setup
	$(DCA) up --build -d
	$(DCI) up --build -d

# Same as `start`, but the infra is built NEG=1 (wrong CA). Enrol with
# `make e2e-neg-ca-test` (expects refusal).
neg-start: setup
	$(DCA) up --build -d
	NEG=1 $(DCI) up --build -d

# ── Compatibility aliases (do not document as the main flow) ──────────────────

start-infra:          start-attestation-infra
start-attester:       start-attestation-attester
request-certificate:  certificate
stop:                 docker-down
clean:                docker-clean-all
test-e2e:             docker-fresh-e2e
e2e-pos-test:         test-submit
