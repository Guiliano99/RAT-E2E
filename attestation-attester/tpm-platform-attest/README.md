# tpm-platform-attest — attester internals

The attester half of the demo: a TCG reference TPM 2.0 simulator, a one-time
provisioner, and the long-lived attester that enrols over CMP.

The [root README](../../README.md) is the front door — what the demo proves, and how to run it.
This file is the reference: per-service breakdown, environment variables, TPM handle layout,
and debugging.

> Development / demo environment only. No physical TPM is required or modified.

---

## Architecture

The demo is **two** Compose projects, started in their own consoles and joined only by
external Docker bridges and the external `tpm-ca` volume (`make setup` creates both). There is
no compose file in this directory.

```
attester project — attestation-attester/docker-compose.yml
┌──────────────────────────────────────────────────────────────┐
│  simulator          TCG reference TPM 2.0, mssim 2321/2322   │
│      ▲                                                       │
│      │ mssim   ┌───────────────────────────────────────────┐ │
│      ├─────────│ provisioner (provision.sh, runs once)     │ │
│      │         │ SRK 0x81000001, EK 0x81010001,            │ │
│      │         │ AK 0x81010002 + CA keypair + AK cert      │ │
│      │         └───────────────────┬───────────────────────┘ │
│      │                             │ writes                  │
│      │         ┌───────────────────▼───────────────────────┐ │
│      └─────────│ tpm-platform-attester (entrypoint.sh)     │ │
│                │ verifies artefacts, then idles.           │ │
│                │ Enrolment is ON DEMAND (docker exec).     │ │
│                └───────────────────┬───────────────────────┘ │
└────────────────────────────────────┼─────────────────────────┘
                                     │ CMP/HTTP over infra-ra
                                     │ 192.168.100.12:5000
infra project — attestation-infra/docker-compose.yml
┌────────────────────────────────────▼─────────────────────────┐
│  mock-ca      mints the nonce, gates issuance on the EAR     │
│      │ POST /submitEvidenceCMP (JSON) over infra-verifier    │
│      ▼                                                       │
│  tpm-verifier appraises the quote → signed EAR               │
└──────────────────────────────────────────────────────────────┘
                          ▲
                          │ both read the shared tpm-ca volume
                          └── ca_cert.pem, ak_cert.pem, pcr_reference.json,
                              ear_signing_key.pem
```

`depends_on` only orders services *within* a project: `simulator → provisioner → attester`
here, and `tpm-verifier → mock-ca` on the infra side. Start order across projects does not
matter — the Verifier re-reads the trust anchor on every appraisal.

| Service | Image | Role |
|---------|-------|------|
| `simulator` | `Dockerfile.simulator` | TCG reference TPM 2.0 simulator (mssim 2321/2322) |
| `provisioner` | `Dockerfile` → `provision.sh` | One-time: SRK/EK/AK handles, CA keypair, AK cert → `tpm-ca` volume |
| `tpm-platform-attester` | `Dockerfile` → `entrypoint.sh` | Generates the TPM subject key and sends the CMP IR with Evidence |

---

## Prerequisites

- Docker ≥ 24 and Docker Compose v2.
- Nothing to check out by hand: OpenSSL, gencmpclient and libattest-py are cloned from their
  pinned public branches during `docker build` (`ARG`s at the top of the `Dockerfile`). The
  `.dockerignore` files keep the build context minimal.

The attester links **libcjson** into its OpenSSL: the fork's `earAttestationResult`
(`1.7.6.5.123`) printer decodes the EAR JWT with cJSON. The build asserts the link
(`ldd … | grep cjson`) — without it the printer silently prints the raw JWT instead.

---

## Running

The attester **idles** after start-up; `docker compose up` alone does not enrol. Enrolment is
on demand, by exec'ing into the running container. From the repo root:

```bash
make setup                        # once: bridges + tpm-ca volume
make start-attestation-infra      # console 1: verifier + MockCA
make start-attestation-attester   # console 2: simulator + provisioner + attester
make certificate                  # console 3: guided enrolment walkthrough
```

When the attester is ready it prints:

```
=== TPM attester ready ===
[entrypoint] Provisioner artefacts verified; TPM up; subject key generated on demand.
[entrypoint] Container staying alive (exec sleep infinity).
```

Two enrolment drivers share the helpers in `entrypoint.sh`:

| Script | Used by | Behaviour |
|--------|---------|-----------|
| `request-certificate.bash` | `make certificate` | Guided walkthrough, pauses at ENTER prompts, forces `CMP_MSG_CAPTURE=1` and `CMP_LOG_ATTEST_STMT=1` |
| `e2e-enroll.sh` | `make test-submit`, `e2e-test.sh` | Non-interactive; for CI |

### Negative tests

`CMP_BAD_ATTEST_SIG=1` corrupts the quote's AK signature before the IR. The Verifier returns
`contraindicated`, the MockCA answers `PKIFailureInfo: badMessageCheck`, and no certificate is
written. It must be passed to an **exec** — a fresh `docker compose run` container would only
idle:

```bash
make test-submit-neg
# equivalently:
docker compose -f attestation-attester/docker-compose.yml \
  exec -e CMP_BAD_ATTEST_SIG=1 tpm-platform-attester /app/e2e-enroll.sh
```

A second negative gate fails one layer earlier, at the AK certificate chain: build the infra
with `NEG=1` so the Verifier trusts a foreign-manufacturer CA (`make start-attestation-infra-neg`,
then `make e2e-neg-ca-test`).

### Teardown

```bash
make docker-down          # stop both projects, keep volumes
make docker-clean-all     # also remove images
```

`tpm-ca` is an **external** volume, so `docker compose down --volumes` will not remove it.

---

## Output artefacts

`./output/` is bind-mounted to `/output` in the attester.

| File | Description |
|------|-------------|
| `enrolled.pem` | The issued X.509 certificate (carries the EAR under `1.7.6.5.123`) |
| `tpm_key.pem` | TPM-resident subject key handle (`TSS2 PRIVATE KEY` PEM) |
| `tpm_key.pub.pem` | Subject key public half (plain PEM, for offline inspection) |
| `ca_cert.pem` | The provisioning CA certificate — the **AK-chain** trust anchor |
| `ak_cert.pem` | The AK certificate (signed by the provisioning CA) |
| `ak.pub.pem` | AK public key (PEM) |
| `mockca_root.pem` | The MockCA enrolment root — verifies `enrolled.pem` (a *different* CA from `ca_cert.pem`) |
| `openssl.cnf` | Generated OpenSSL config used during key generation |

With `CMP_MSG_CAPTURE=1` (which `request-certificate.bash` forces, so every walkthrough run
produces them):

| File | Description |
|------|-------------|
| `nonce-exchange.txt` | The `genm`/`genp` nonce exchange decoded to readable ASN.1 |
| `req1-genm.der` / `rsp1-genp.der` | Raw nonce request / response `PKIMessage` DER |
| `req2-ir.der` / `rsp2-ip.der` | Raw certificate request / response `PKIMessage` DER |

### Inspecting artefacts on the host

```bash
# The issued certificate — the fork's OpenSSL also decodes the EAR extension inline
openssl x509 -in output/enrolled.pem -noout -text

# enrolled.pem chains to the MockCA enrolment root — NOT to ca_cert.pem,
# which anchors the AK chain and will fail here.
openssl verify -CAfile output/mockca_root.pem output/enrolled.pem

# The AK certificate chains to the provisioning CA
openssl verify -CAfile output/ca_cert.pem output/ak_cert.pem
```

---

## Environment variables

### `tpm-platform-attester`

| Variable | Default | Description |
|----------|---------|-------------|
| `TPM2TOOLS_TCTI` | `mssim:host=simulator,port=2321` | TCTI for all `tpm2_*` commands |
| `TPM2OPENSSL_TCTI` | *(falls back to `TPM2TOOLS_TCTI`)* | TCTI written into `openssl.cnf` for the tpm2 provider |
| `CMP_ATTEST_TYPE` | `quote` | `quote` → `TPM2_Quote` / `TcgAttestQuote` (2.23.133.20.2); `certify` → `TPM2_Certify` / `TcgAttestCertify` (2.23.133.20.1) |
| `TPM_QUOTE_PCRS` | `0,1,2,3,4` | PCRs the quote covers; must match the Verifier's baseline |
| `CMP_SERVER` | *(none; compose sets `192.168.100.12:5000`)* | `host:port` of the CMP server (MockCA). Enrolment is skipped if unset |
| `CMP_PATH` | `issuing` | CMP URL path |
| `CMP_RECIPIENT` | `/CN=CMP-Test-Suite-CA` | CMP `recipient` field |
| `CMP_SUBJECT` | `/CN=tpm-platform-attester` | CMP `subject` field |
| `CMP_REF` | `tpm-platform-attester` | CMP MAC reference value |
| `CMP_SECRET` | `SiemensIT` | Shared secret for MAC-based CMP authentication |
| `CMP_POPO` | `0` | `0` = raVerified; `1` = signature POPO via tpm2-abrmd |
| `CMP_MSG_CAPTURE` | `0` | `1` dumps the four CMP `PKIMessage`s as DER under `./output` |
| `CMP_BAD_ATTEST_SIG` | `0` | `1` corrupts the AK signature (negative test) |
| `CMP_LOG_ATTEST_STMT` | `0` | `1` renders the typed attestation fields into the CMP client log |
| `TPM_KEY_ATTEST_OID` | `1.3.6.1.4.1.99999.4` | Key-attestation request-type OID; must match the MockCA |

### `provisioner`

| Variable | Default | Description |
|----------|---------|-------------|
| `TPM2TOOLS_TCTI` | `mssim:host=simulator,port=2321` | TCTI for all `tpm2_*` commands |
| `PROVISION_MODE` | `static` | `static` skips if the handles exist; `fresh` evicts and re-provisions |

### `tpm-verifier` (infra project)

| Variable | Default | Description |
|----------|---------|-------------|
| `TRUSTED_CA_CERT_FILE` | `/tpm-ca/ca_cert.pem` | Anchor for the AK certificate chain; re-read on every appraisal |
| `PCR_REFERENCE_VALUES_FILE` | `/tpm-ca/pcr_reference.json` | The PCR baseline. Unset ⇒ appraisal is impossible and Evidence is rejected |
| `EAR_SIGNING_KEY_FILE` | `/tpm-ca/ear_signing_key.pem` | Key the EAR is signed with |
| `TPM_QUOTE_PCRS` | `0,1,2,3,4` | PCRs the appraisal requires |
| `VERIFIER_ALLOWED_OIDS` | `2.23.133.20.2` | Accepted statement OIDs |
| `VERIFIER_SUBMIT_PATH` | `/submitEvidenceCMP` | Evidence submission route |
| `LISTEN_PORT` | `8444` | HTTP port |

### `mock-ca` (infra project)

| Variable | Default | Description |
|----------|---------|-------------|
| `VERIFIER_OID_ROUTES` | `{"2.23.133.20.2": …, "2.23.133.20.1": …}` | JSON map: statement OID → Verifier URL |
| `VERIFIER_URL_FALLBACK` | `http://tpm-verifier:8444` | Used when the OID has no route |
| `TPM_QUOTE_PCRS` | `0,1,2,3,4` | PCR selection offered in the nonce response |
| `TPM_KEY_ATTEST_OID` | `1.3.6.1.4.1.99999.4` | Key-attestation request-type OID |
| `ALLOW_RECIPIENT_NONCE` | `true` | gencmpclient echoes the genp `senderNonce` back as `recipNonce` in the IR, which a default MockCA rejects on an initial request. Required here |

---

## Attestation protocol detail

Field values below are a live capture (`CMP_MSG_CAPTURE=1` → `output/*.der`, decoded by
`pretty_print_stmt.py` → `output/nonce-exchange.txt`).

**1 — nonce exchange (genm/genp).** `cmpClient` asks the RA/CA for a nonce; the RA/CA mints 32
random bytes and answers with the quote parameters. The Verifier is not involved.

```
genm  InfoTypeAndValue.infoType = 1.2.840.113549.1.9.16.2.8888
      NonceRequest.reqTypeInfo { type = 1.2.3.4.5
        reqInfo = TPM20QuoteReqInfo { certificateName = { ak-1, ak-2, ak-3 }
                                      supportedHashAlgo = { 11 } } }

genp  InfoTypeAndValue.infoType = 1.2.840.113549.1.9.16.2.8889
      NonceResponse { nonce = 32 bytes, expiry = 50
        respTypeInfo { type = 1.2.3.4.6
          respInfo = TPM20QuoteRespInfo { certificateName = ak-1
                                          pcrSelection = { 0, 1, 2, 3, 4 }
                                          hashAlgo = 11 (TPM_ALG_SHA256) } } }
```

> These OIDs are placeholders this demo puts on the wire, not the values
> draft-ietf-lamps-attestation-freshness assigns (`id-it-nonceRequest` 1.3.6.1.5.5.7.4.98 /
> `id-it-nonceResponse` …4.99).

**2 — Evidence (attester).** `cmpClient` calls into libattest through the embedded Python
bridge (`libattest.attester.evidence_bridge`), which runs `TPM2_Quote` over the selected PCRs
with the nonce as `qualifyingData`, and returns a `TcgAttestQuote` (2.23.133.20.2). The CSR
carries it in the evidence attribute `1.2.840.113549.1.9.16.2.59`
(draft-ietf-lamps-csr-attestation). libattest is on the enrolment critical path, not a
diagnostic aid.

**3 — appraisal (RA/CA + Verifier).** The MockCA routes the statement OID via
`VERIFIER_OID_ROUTES` and `POST`s the Evidence as JSON to `/submitEvidenceCMP`. The Verifier
checks the AK certificate chain, the AK signature over `TPMS_ATTEST`, the nonce in
`extraData`, and the PCR digest against the baseline, then returns a signed EAR. On
`ear.status: affirming` the MockCA issues the certificate and embeds the EAR under
`1.7.6.5.123`; otherwise it rejects with `badMessageCheck` and issues nothing.

---

## TCTI conflict — why `OPENSSL_CONF` is unset for cmpClient

`tpm2-openssl` calls `Tss2_TctiLdr_Initialize()` eagerly in `OSSL_provider_init`, opening a TCP
connection to mssim at **provider load time**. If `OPENSSL_CONF` is set when `cmpClient`
starts, the provider loads during OpenSSL init and occupies the single mssim connection; the
TPM code then blocks waiting for a second connection that never comes.

`entrypoint.sh` therefore runs `cmpClient` in a subshell with the variable unset, so only the
default provider loads:

```bash
(
    unset OPENSSL_CONF
    cmpClient -cmd ir ...
)
```

---

## Dockerfile stages

Three thin stages clone the pinned branches (so the heavy build stage's cache survives a branch
move), then one build stage compiles, in order:

| # | Component | Version | Notes |
|---|-----------|---------|-------|
| 1 | **OpenSSL** (fork) | `3.6.0-dev` | `demo/docker_RATS2_OLD_V9`; `shared`, `-lcjson` for the EAR printer |
| 2 | **tpm2-tss** | `4.1.3` | `--with-crypto=ossl --disable-fapi`; links the fork |
| 2b | **tpm2-abrmd** | `3.0.0` | Resource manager; only used by `CMP_POPO=1` |
| 3 | **tpm2-openssl** | `1.3.0` | Provider installed into OpenSSL's `MODULESDIR` |
| 4 | **gencmpclient** (fork) | `demo/docker_RATS2_TPMV4_COSE` | `cmpClient` with the `-tpm_*` flags and the embedded Python bridge |
| 4b | **libattest-py** | `UpdateV8_1` | Evidence generation + typed ASN.1; installed with pip |
| 5 | **tpm2-tools** | `5.7` | `tpm2_*` commands used by `provision.sh` |

`PKG_CONFIG_PATH` and `LD_LIBRARY_PATH` point every step at the just-built OpenSSL rather than
any system copy.

---

## Debugging

All commands below are run from the repo root. `tpm-verifier` and `mock-ca` are services of the
**infra** project — `docker compose -f attestation-attester/… logs mock-ca` will not find them.

```bash
# Shell in the running attester
docker compose -f attestation-attester/docker-compose.yml exec tpm-platform-attester bash
openssl list -providers
tpm2_getcap handles-persistent      # expect 0x81000001, 0x81010001, 0x81010002

# Logs
docker compose -f attestation-infra/docker-compose.yml logs tpm-verifier
docker compose -f attestation-infra/docker-compose.yml logs mock-ca

make docker-status                  # containers + images of both projects
```

---

## Automated regression test

`./e2e-test.sh` (or `make docker-fresh-e2e` to rebuild first) runs the positive and negative
cases in one shot. It brings the stack up under its **own** project names (`tpm-att` /
`tpm-inf`); the static IPs collide, so stop other instances first.

```bash
./e2e-test.sh                  # positive + negative
./e2e-test.sh --build          # rebuild images first
./e2e-test.sh --positive-only
./e2e-test.sh --negative-only
./e2e-test.sh --keep           # leave the stack running afterwards
```

Gates asserted:

| Gate | Meaning |
|------|---------|
| `POS:cert issued` | `enrolled.pem` was produced |
| `POS:cert signed by CA` | It chains to the MockCA enrolment root |
| `POS:cert SPKI matches TPM key` | Its public key is the TPM-resident key |
| `POS:cert carries EAR extension` | The EAR is present under `1.7.6.5.123` |
| `NEG:enrolment fails (non-zero)` | The corrupted-signature run exits non-zero |
| `NEG:no cert produced` | No certificate is written |

The MockCA's `PKIFailureInfo: badMessageCheck` line is logged for information only — it is not
a pass criterion.

---

## Real-TPM portability

The same image and entrypoint work against a real TPM 2.0: change the TCTI strings and
bind-mount the resource-manager device, for **both** `provisioner` and `tpm-platform-attester`.

```yaml
tpm-platform-attester:
  environment:
    TPM2TOOLS_TCTI:   "device:/dev/tpmrm0"
    TPM2OPENSSL_TCTI: "device:/dev/tpmrm0"
  devices:
    - /dev/tpmrm0:/dev/tpmrm0
```

No source changes are required. The mssim-specific quirks (single-connection TCTI,
`tpm2_flushcontext` after every operation) are safe no-ops on real hardware. Note that real
PCRs are not all-zero, so `pcr_reference.json` must carry the real baseline.

---

## Known build issues

**`LT_LIB_DLLOAD` undefined macro** — `libltdl-dev` missing before `autoreconf` in tpm2-tss.
It is in the Dockerfile's `apt-get install` list.

**`ASN1_OCTET_STRING` incomplete typedef** — tpm2-tss FAPI and tpm2-openssl 1.2.x access
`asn1_string_st` members directly, which are opaque in newer OpenSSL. Fixed by building
tpm2-tss with `--disable-fapi` and using tpm2-openssl 1.3.0.

**`Python.h` not found** — the gencmpclient fork embeds a Python bridge, so the image needs
`python3-dev` and `libpython3.x`; both are in the Dockerfile.
