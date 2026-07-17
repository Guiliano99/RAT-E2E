# SPDX-FileCopyrightText: Copyright 2026 Siemens AG
#
# SPDX-License-Identifier: Apache-2.0

"""HTTP service wrapping the TPM verifier backend (RA-issued nonce model).

The MockCA owns the nonce state and submits each piece of evidence together
with the expected nonce in a single POST call; the verifier is stateless
between submissions (constraint.md §9 revised).

Endpoints (consumed by ``mock_ca.remote_att_mockca.attestation_verifier``):

* ``POST /submitEvidenceCMP``
  Body (JSON)::

      {
          "nonce":          "<base64>",   // the RA-issued nonce
          "evidence":       "<base64>",   // DER of the AttestationBundle
          "oid":            "2.23.133.20.2",  // OPTIONAL statement-type OID
          "resp_info_json": {             // OPTIONAL NonceResponse.respInfo as
              "pcrs": [0, 1, 2, 3, 4],    // plain JSON (NOT base64/DER); for the
              "hashAlgId": 11             // TPM profile this is TpmAttestationParams
          }
      }

  Response: ``{"ear": "<EAR JWT compact-serialised>"}`` — the verdict is in
  the EAR ``submods``; the caller checks ``ear.status == "affirming"``.

* ``GET /ear-verification-key``
  PEM of the EAR-JWT signing public key (also serves as the healthcheck).

Each submission opens one verification session; the session ID is logged in
the Veraison challenge-response URL form so per-enrollment session
distinctness is observable from the service log (gate G4).

Env vars:
    LISTEN_PORT            -- TCP port to bind (default 8444).
    EAR_SIGNING_KEY_FILE   -- PEM EC P-256 private key; created on first run.
    TRUSTED_CA_CERT_FILE   -- consumed by tpm_verifier (AK chain anchor).
    PCR_REFERENCE_VALUES_FILE -- consumed by tpm_verifier (G2 appraisal).
"""

from __future__ import annotations

import base64
import json
import logging
import os
import time
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature
from pyasn1.codec.der import decoder as asn1_decoder
from pyasn1.codec.der import encoder as asn1_encoder

from tpm_verifier import VerifierBackend

# Reuse libattest's AttestationBundle/AttestationStatement (the C client emits a
# wire-identical SEQUENCE OF X509 in `certs` — the `certificate` arm of
# LimitedCertChoices) instead of redefining them here.
from libattest.formats.csrattest.csr_attest_structures import (
    AttestationBundle,
    get_attestation_bundle_certs,
)
# OID-keyed respInfo JSON↔DER codec: the MockCA→verifier hop carries respInfo
# as JSON; we re-encode to DER here so the backend's G_PCR_BIND stays on DER.
from libattest.formats.respinfo import DEFAULT_RESP_INFO_REGISTRY

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(name)s: %(message)s",
)
logger = logging.getLogger("verifier_service")


# ---------------------------------------------------------------------------
# EAR JWT (ES256) helpers
# ---------------------------------------------------------------------------

def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _load_or_create_signing_key(path: str) -> ec.EllipticCurvePrivateKey:
    """Load the EAR signing key, creating it atomically on first run.

    The key file lives on the shared tpm-ca volume, so another service
    instance may create it concurrently.  Creation writes a unique temp file
    and renames it into place (atomic on POSIX), then re-reads the published
    file, so concurrent starters always converge on the same key; a read or
    create that races another writer simply retries.
    """
    for attempt in range(20):
        try:
            with open(path, "rb") as f:
                key = serialization.load_pem_private_key(f.read(), password=None)
            if not isinstance(key, ec.EllipticCurvePrivateKey):
                raise SystemExit(f"{path} is not an EC private key")
            logger.info("EAR signing key loaded from %s", path)
            return key
        except FileNotFoundError:
            pass
        except OSError as exc:
            # Transient volume/IO trouble — retry, bounded by the loop.
            logger.warning("EAR signing key at %s unreadable (%s) — retrying", path, exc)
            time.sleep(0.2)
            continue
        except (ValueError, TypeError):
            # Concurrent writer mid-write, corrupt file, or encrypted PEM
            # (TypeError) — retry briefly; SystemExit after the loop bounds it.
            logger.warning("EAR signing key at %s not (yet) readable — retrying", path)
            time.sleep(0.2)
            continue

        key = ec.generate_private_key(ec.SECP256R1())
        pem = key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
        # uuid4, NOT os.getpid(): containerised instances each run as PID 1,
        # so pid-based names collide on the shared volume and O_EXCL raises.
        tmp_path = f"{path}.{uuid.uuid4().hex}.tmp"
        try:
            fd = os.open(tmp_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(fd, "wb") as f:
                f.write(pem)
            os.rename(tmp_path, path)
        except OSError as exc:
            logger.warning("EAR signing key create race at %s (%s) — retrying", path, exc)
            time.sleep(0.2)
            continue
        logger.info("EAR signing key created at %s", path)
        # Last writer wins: re-read the published file on the next loop pass
        # so every instance returns the same key even after a create race.
        time.sleep(0.2)
    raise SystemExit(f"could not load or create EAR signing key at {path}")


def _build_tpm_submod(verdict: str, tpm_claims: dict | None) -> dict:
    """Assemble the TPM submodule of the EAR: verdict + custom TPM EAT claims.

    Keys follow the EAR/EAT convention — the standard ``ear.status`` plus
    namespaced ``tpm.*`` claims carrying the appraised platform state.  Only
    measurements the verifier actually bound to the AK signature are included,
    so a relying party reading the issued certificate can see *what* was
    attested (the PCR digest and, when carried, the per-PCR values) rather than
    only the affirming/contraindicated verdict.
    """
    submod: dict = {"ear.status": verdict}
    if tpm_claims:
        submod["tpm.pcr-digest"] = tpm_claims["pcr-digest"]
        submod["tpm.hash-alg"] = tpm_claims["hash-alg"]
        submod["tpm.pcr-selection"] = tpm_claims["pcr-selection"]
        submod["tpm.pcr-digest-ref-matched"] = tpm_claims.get(
            "pcr-digest-ref-matched", False
        )
        # Per-PCR values are present only once G_PCR_VALUES_BIND has confirmed
        # SHA256(values) == the signed pcrDigest (see tpm_verifier._check_quote).
        if "pcrs" in tpm_claims:
            submod["tpm.pcrs"] = tpm_claims["pcrs"]
            submod["tpm.pcr-digest-recomputed"] = tpm_claims.get(
                "pcr-digest-recomputed", False
            )
    return submod


def _sign_ear_jwt(
    key: ec.EllipticCurvePrivateKey,
    verdict: str,
    nonce: bytes,
    session_id: str,
    tpm_claims: dict | None = None,
) -> str:
    """Build a minimal ar4si-style EAR JWT with an ES256 (raw R||S) signature.

    When *tpm_claims* is given (quote profile), the appraised, signature-bound
    PCR measurements are folded into the TPM submod as a custom TPM EAT.
    """
    header = {"alg": "ES256", "typ": "JWT"}
    payload = {
        "eat_profile": "tag:github.com,2023:veraison/ear",
        "iat": int(time.time()),
        "ear.verifier-id": {"developer": "remote-attest-e2e", "build": "tpm-verifier"},
        "eat_nonce": _b64url(nonce),
        "session": session_id,
        "submods": {"TPM": _build_tpm_submod(verdict, tpm_claims)},
    }
    message = (
        _b64url(json.dumps(header, separators=(",", ":")).encode())
        + "."
        + _b64url(json.dumps(payload, separators=(",", ":")).encode())
    )
    der_sig = key.sign(message.encode("ascii"), ec.ECDSA(hashes.SHA256()))
    r, s = decode_dss_signature(der_sig)
    raw_sig = r.to_bytes(32, "big") + s.to_bytes(32, "big")
    return message + "." + _b64url(raw_sig)


# ---------------------------------------------------------------------------
# Request handling
# ---------------------------------------------------------------------------

_SIGNING_KEY: ec.EllipticCurvePrivateKey | None = None
_VERIFICATION_KEY_PEM: bytes = b""

_DEFAULT_QUOTE_OID = "2.23.133.20.2"

# Submit endpoint path. Configurable so each example can use a distinct,
# non-colliding endpoint while sharing this one verifier service (set the same
# VERIFIER_SUBMIT_PATH on the MockCA so client and server agree). The default
# keeps the existing platform example working unchanged. Only one example runs
# at a time, so a single configurable path avoids duplicating the service.
_SUBMIT_PATH = (os.environ.get("VERIFIER_SUBMIT_PATH") or "/submitEvidenceCMP").strip()

# Opt-in: log the full received JSON payload (VERIFIER_LOG_PAYLOAD=1) so a user
# wiring their own verifier can see exactly what the MockCA sends.
_LOG_PAYLOAD = (os.environ.get("VERIFIER_LOG_PAYLOAD") or "").strip().lower() in (
    "1", "true", "yes",
)


def _allowed_oids() -> frozenset[str]:
    """Statement OIDs this verifier will appraise.

    The platform-attestation profile MUST accept only TcgAttestQuote
    (2.23.133.20.2): its backend is the one that appraises PCRs against the
    reference baseline.  TcgAttestCertify (2.23.133.20.1) performs no PCR
    appraisal, so honouring a client-chosen certify OID here would let any
    holder of a CA-certified AK obtain an affirming verdict for an
    unappraised platform state — an attestation bypass.  Override with
    VERIFIER_ALLOWED_OIDS (comma-separated) only when adding the
    key-attestation profile later.
    """
    raw = os.environ.get("VERIFIER_ALLOWED_OIDS", "").strip()
    if not raw:
        return frozenset({_DEFAULT_QUOTE_OID})
    return frozenset(o.strip() for o in raw.split(",") if o.strip())


def _verify_submission(body: dict) -> tuple[int, dict]:
    """Run one evidence verification; returns (http_status, response_json)."""
    try:
        nonce = base64.b64decode(body["nonce"])
        bundle_der = base64.b64decode(body["evidence"])
    except (KeyError, ValueError, TypeError) as exc:
        # TypeError: field is null / not a string (b64decode rejects it).
        return 400, {"error": f"bad request body: {exc}"}
    oid = body.get("oid") or _DEFAULT_QUOTE_OID
    allowed = _allowed_oids()
    if oid not in allowed:
        # Refuse a profile this verifier is not configured to appraise, rather
        # than dispatching to a backend that would skip PCR appraisal.
        session_id = uuid.uuid4().hex
        logger.warning(
            "session %s: refusing evidence OID %s (allowed: %s)",
            session_id, oid, ",".join(sorted(allowed)),
        )
        assert _SIGNING_KEY is not None
        ear = _sign_ear_jwt(_SIGNING_KEY, "contraindicated", nonce, session_id)
        return 200, {"ear": ear}
    # respInfo arrives as a plain JSON object (NOT base64/DER) on this internal
    # MockCA→verifier hop.  Re-encode it to DER TPM20QuoteRespInfo via the
    # libattest codec keyed by the statement OID, so the backend's G_PCR_BIND
    # check (which still consumes DER) stays unchanged.
    pcr_selection_der = None
    resp_info_json = body.get("resp_info_json")
    if resp_info_json is not None:
        if not isinstance(resp_info_json, dict):
            return 400, {"error": "resp_info_json must be a JSON object"}
        if not DEFAULT_RESP_INFO_REGISTRY.is_registered(oid):
            return 400, {"error": f"no respInfo codec registered for oid {oid}"}
        try:
            pcr_selection_der = DEFAULT_RESP_INFO_REGISTRY.from_json(oid, resp_info_json)
        except (ValueError, KeyError) as exc:
            return 400, {"error": f"bad resp_info_json: {exc}"}

    # One verification session per submission (G4: distinct session IDs).
    session_id = uuid.uuid4().hex
    logger.info(
        "newSession /challenge-response/v1/session/%s (oid=%s, evidence=%dB, nonce=%dB)",
        session_id, oid, len(bundle_der), len(nonce),
    )

    verdict = "contraindicated"
    tpm_claims: dict | None = None
    try:
        bundle, rest = asn1_decoder.decode(bundle_der, asn1Spec=AttestationBundle())
        if rest:
            raise ValueError("trailing bytes after AttestationBundle")

        stmt_der = None
        for stmt in bundle["attestations"]:
            if str(stmt["type"]) == oid:
                stmt_der = bytes(stmt["stmt"])
                break
        if stmt_der is None:
            raise ValueError(f"no AttestationStatement with type {oid} in bundle")

        # certs are SEQUENCE OF X509 on the wire (the `certificate` arm of
        # LimitedCertChoices); re-encode each to DER for cryptography.x509.
        ak_chain = [asn1_encoder.encode(cert) for cert in get_attestation_bundle_certs(bundle)]
        if not ak_chain:
            raise ValueError("AttestationBundle carries no AK certificate")

        backend = VerifierBackend.for_oid(oid)
        verdict, tpm_claims = backend.verify_detailed(
            stmt_der,
            ak_chain,
            expected_nonce=nonce,
            pcr_selection_der=pcr_selection_der,
        )
    except Exception as exc:  # noqa: BLE001
        logger.warning("session %s: evidence rejected: %s", session_id, exc)
        verdict = "contraindicated"
        tpm_claims = None

    logger.info(
        "session /challenge-response/v1/session/%s verdict: %s",
        session_id, verdict,
    )
    assert _SIGNING_KEY is not None
    ear = _sign_ear_jwt(_SIGNING_KEY, verdict, nonce, session_id, tpm_claims)
    return 200, {"ear": ear}


class _Handler(BaseHTTPRequestHandler):
    # Route Python logging instead of the default stderr printf format.
    def log_message(self, fmt: str, *args) -> None:  # noqa: A003
        logger.info("%s %s", self.address_string(), fmt % args)

    def _respond(self, status: int, content_type: str, body: bytes) -> None:
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self) -> None:  # noqa: N802
        if self.path == "/ear-verification-key":
            self._respond(200, "application/x-pem-file", _VERIFICATION_KEY_PEM)
            return
        self._respond(404, "application/json", b'{"error": "not found"}')

    def do_POST(self) -> None:  # noqa: N802
        if self.path != _SUBMIT_PATH:
            self._respond(404, "application/json", b'{"error": "not found"}')
            return
        try:
            length = int(self.headers.get("Content-Length", "0"))
            body = json.loads(self.rfile.read(length))
        except (ValueError, json.JSONDecodeError) as exc:
            self._respond(
                400, "application/json",
                json.dumps({"error": f"bad JSON: {exc}"}).encode(),
            )
            return
        if not isinstance(body, dict):
            self._respond(
                400, "application/json",
                b'{"error": "JSON body must be an object"}',
            )
            return
        if _LOG_PAYLOAD:
            logger.info("received submit payload at %s: %s", self.path, json.dumps(body))
        status, response = _verify_submission(body)
        self._respond(status, "application/json", json.dumps(response).encode())


def main() -> None:
    global _SIGNING_KEY, _VERIFICATION_KEY_PEM

    port = int(os.environ.get("LISTEN_PORT", "8444"))
    key_file = os.environ.get("EAR_SIGNING_KEY_FILE", "/tpm-ca/ear_signing_key.pem")

    _SIGNING_KEY = _load_or_create_signing_key(key_file)
    _VERIFICATION_KEY_PEM = _SIGNING_KEY.public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )

    server = ThreadingHTTPServer(("0.0.0.0", port), _Handler)
    logger.info(
        "tpm-verifier service listening on :%d (submit path %s)", port, _SUBMIT_PATH
    )
    server.serve_forever()


if __name__ == "__main__":
    main()
