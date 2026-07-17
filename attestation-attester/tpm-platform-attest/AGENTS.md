# TPM PLATFORM ATTESTATION — ATTESTER SIDE

The attester half (end entity + TPM) of the TPMPCRDemo stack: TPM 2.0 platform
attestation with CMP certificate enrolment.

The demo is **two** Compose projects, run from the repo root:

| Project | File | Services |
|---------|------|----------|
| attester (this side) | `attestation-attester/docker-compose.yml` | `simulator`, `provisioner`, `tpm-platform-attester` |
| infra | `attestation-infra/docker-compose.yml` | `tpm-verifier`, `mock-ca` |

They meet only on the external bridges (`infra-ra`, `infra-verifier`,
`provisioning`) and the external `tpm-ca` volume — `make setup` creates both.
There is no compose file in this directory.

## STRUCTURE

```
tpm-platform-attest/
├── Dockerfile                # attester + provisioner image: three clone stages
│                             # (openssl / gencmpclient / libattest) → one build stage
├── Dockerfile.simulator      # TCG reference TPM 2.0 simulator
├── *.dockerignore            # keep the build contexts minimal
├── provision.sh              # one-time: SRK/EK/AK handles + CA keypair + AK cert
├── entrypoint.sh             # attester flow: keygen → cmpClient IR with Evidence
├── request-certificate.bash  # on-demand enrolment (interactive)
├── e2e-enroll.sh             # non-interactive enrolment, used by the gates
├── e2e-test.sh               # positive + negative regression test
├── pretty_print_stmt.py      # decodes the genm/genp nonce exchange
├── output/                   # bind-mounted artefacts (enrolled.pem, tpm_key.pem, ...)
└── README.md                 # architecture, env vars, debugging, TCTI conflict
```

Diagrams live in `figures/` at the **repo root**, not here.

## WHERE TO LOOK

| Task | Location | Notes |
|------|----------|-------|
| Change service start order | `../docker-compose.yml` `depends_on` | `simulator → provisioner → attester` |
| Change TPM key template | `provision.sh` | SRK `0x81000001`, EK `0x81010001`, AK `0x81010002` |
| Change enrolment flow | `entrypoint.sh` | `openssl genpkey` + `cmpClient -cmd ir` |
| Change verifier trust anchor | `../../attestation-infra/docker-compose.yml` `TRUSTED_CA_CERT_FILE` | `/tpm-ca/ca_cert.pem` (shared volume) |
| Change MockCA verifier routing | `../../attestation-infra/docker-compose.yml` `VERIFIER_OID_ROUTES` / `VERIFIER_URL_FALLBACK` | JSON env vars on `mock-ca` |
| Run the full e2e | `./e2e-test.sh` or `make docker-fresh-e2e` | flags: `--build`, `--positive-only`, `--negative-only`, `--keep` |
| Positive / negative gate on a running stack | `make test-submit` / `make test-submit-neg` | negative uses `CMP_BAD_ATTEST_SIG=1` |
| Wrong-CA negative gate | `make start-attestation-infra-neg` then `make e2e-neg-ca-test` | infra must be built with `NEG=1` |
| Read the EAR from the issued cert | `openssl x509 -in enrolled.pem -text -noout` | fork decodes the EAR extension inline; stock OpenSSL prints the raw JWT |

## CONVENTIONS

- **Build context is the repo root** (`context: ..` from `attestation-attester/`).
- **All sources are cloned from published branches during build** — no local
  checkouts, no named BuildKit contexts. Branch defaults are `ARG`s at the top of
  the `Dockerfile`: `openssl@demo/docker_RATS2_OLD_V9`,
  `gencmpclient@demo/docker_RATS2_TPMV4_COSE`, `libattest-py@UpdateV8_1`.
- **`libcjson-dev` + `-lcjson`** are required: the OpenSSL fork's
  `earAttestationResult` (1.7.6.5.123) printer decodes the EAR JWT with cJSON, so
  libcrypto itself links it. The build asserts the link with `ldd | grep cjson` —
  without it the printer silently falls back to printing the raw JWT.
- **`tpm-ca` external volume** shared across provisioner, verifier, and attester:
  CA cert, AK cert, EAR signing key, PCR reference values.
- **`/output` bind mount** → `./output/` on the host.
- **Health checks**: simulator `kill -0 1` (never raw TCP); verifier `GET
  /ear-verification-key` (8444); mockca `GET /root-cert` (5000).

## ANTI-PATTERNS

- **DO NOT** use `tpm2_startup -c` as a health check — raw TCP probes and extra
  commands disturb the mssim connection; `kill -0 1` suffices.
- **DO NOT** set `OPENSSL_CONF` when running `cmpClient` — the tpm2 provider's
  eager TCTI init blocks the mssim single-connection port.
- **DO NOT** use `swtpm` on Ubuntu 24.04 — `libtpms 0.9.3` has an
  `HR_TRANSIENT_AVAIL = 0` bug; use the TCG reference simulator.
- **DO NOT** export TPM keys to PEM — the subject key stays TPM-resident
  (`TSS2 PRIVATE KEY` format only).
- **DO NOT** build the two projects under different project names — `e2e-test.sh`
  uses its own (`tpm-att` / `tpm-inf`), and the static IPs collide, so only one
  set of projects can run at a time.

## NOTES

- The provisioner is idempotent: with `PROVISION_MODE=static` (default) it skips
  every step if handles `0x81000001/0x81010001/0x81010002` already exist. Set
  `PROVISION_MODE=fresh` to evict and re-create.
- `CMP_BAD_ATTEST_SIG=1` is the only Evidence-corrupting negative switch; it
  corrupts the quote's AK signature, the Verifier rejects, and the MockCA answers
  `PKIFailureInfo: badMessageCheck`.
