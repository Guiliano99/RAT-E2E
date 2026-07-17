# SPDX-FileCopyrightText: Copyright 2026 Siemens AG
#
# SPDX-License-Identifier: Apache-2.0

"""TPM verifier backend for TcgAttestCertify (G1) and TcgAttestQuote (G2).

This service reuses ``libattest-py`` for everything it can — the ASN.1
structures (``TcgAttestCertify``, ``TpmAttestationParams``) and the TPMS_ATTEST
parsers (``extract_qualifying_data`` / ``extract_quote_info`` /
``extract_certify_name``) — instead of redefining them.  Signature verification
is split per the verifier design:

* the **AK certificate** chain is validated with ``cryptography`` (X.509), via
  ``libattest.verifier.trust.validate_ek_chain``;
* the **attestation-statement signature** (AK over ``TPMS_ATTEST``) is verified
  with ``tpm2-pytss`` (``libattest.formats.tpm.tpm_marshal.verify_tpm_signature``),
  which handles the TPM scheme/hash/encoding (RSASSA / RSAPSS / ECDSA).

Env vars (read at verify time):
    TRUSTED_CA_CERT_FILE  -- PEM file with the trust-anchor CA certificate.
    PCR_REFERENCE_VALUES_FILE -- JSON {"expected_pcr_digest_hex": "<hex>"}.
"""

from __future__ import annotations

import hashlib
import json
import logging
import os

from cryptography import x509
from cryptography.exceptions import InvalidSignature
from pyasn1.codec.der import decoder as asn1_decoder

from libattest.formats.tpm import (
    TcgAttestCertify,
    compute_tpm_name,
    decode_tpm20_quote_resp_info,
    extract_certify_name,
    extract_qualifying_data,
    extract_quote_info,
    pcr_mask_to_indices,
    verify_tpm_signature,
)
from libattest.verifier.trust import validate_ek_chain

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# TPM constants
# ---------------------------------------------------------------------------

_TPM_GENERATED_VALUE = b"\xff\x54\x43\x47"  # b"\xffTCG"
_TPM_ST_ATTEST_CERTIFY = 0x8017
_TPM_ST_ATTEST_QUOTE = 0x8018
_TPM_ALG_SHA256 = 0x000B

# OIDs
_OID_TCG_ATTEST_CERTIFY = "2.23.133.20.1"
_OID_TCG_ATTEST_QUOTE = "2.23.133.20.2"

# ---------------------------------------------------------------------------
# Trusted CA certificate (trust anchor for the AK certificate chain)
# ---------------------------------------------------------------------------
#
# Read FRESH on every verification rather than cached at import time.  In this
# demo the trust anchor is generated at runtime by the attester's provisioner
# and shared over the tpm-ca volume, so /tpm-ca/ca_cert.pem may be written — or
# replaced by a re-provisioned CA — AFTER this process has started.  Caching it
# at import made the verifier trust a stale CA (or crash if the file was not
# there yet) depending on container start order; re-reading per request keeps
# it correct regardless of ordering and re-provisioning.


def _load_trusted_ca_cert() -> x509.Certificate | None:
    """Return the trust-anchor CA cert from TRUSTED_CA_CERT_FILE, or None.

    None (rather than an exception) is returned when the env var is unset or
    the file cannot be read/parsed yet, so the caller rejects the evidence as
    ``contraindicated`` instead of the service crashing.
    """
    path = os.environ.get("TRUSTED_CA_CERT_FILE")
    if not path:
        return None
    try:
        with open(path, "rb") as f:
            return x509.load_pem_x509_certificate(f.read())
    except (OSError, ValueError) as exc:
        logger.warning(
            "could not load TRUSTED_CA_CERT_FILE=%s: %s: %s",
            path, type(exc).__name__, exc,
        )
        return None


# ---------------------------------------------------------------------------
# PCR-bank hash helpers
# ---------------------------------------------------------------------------

# TPM_ALG_ID → (EAT-claim name, hashlib factory, digest size in bytes).
# Only SHA-256 is in scope for this profile (tpm_ops.c's fixed bank); extend
# this map when adding hash agility.
_TPM_HASH_ALGS = {
    _TPM_ALG_SHA256: ("sha256", hashlib.sha256, 32),
}


def _hash_alg_name(alg_id: int) -> str:
    """Human/EAT name for a TPM hash-alg id; falls back to a hex tag."""
    entry = _TPM_HASH_ALGS.get(alg_id)
    return entry[0] if entry is not None else f"alg-{alg_id:#06x}"


def _pcr_digest_size(alg_id: int) -> int:
    """Digest size (bytes) of a TPM PCR bank; raises on unknown algs."""
    entry = _TPM_HASH_ALGS.get(alg_id)
    if entry is None:
        raise ValueError(f"unsupported PCR bank hash alg {alg_id:#06x}")
    return entry[2]


def _hash_pcr_values(alg_id: int, data: bytes) -> bytes:
    """Compute the PCR-bank hash over *data*; raises on unknown algs."""
    entry = _TPM_HASH_ALGS.get(alg_id)
    if entry is None:
        raise ValueError(f"unsupported PCR bank hash alg {alg_id:#06x}")
    return entry[1](data).digest()


def _optional_octets(tcg) -> bytes | None:
    """Return the bytes of TcgAttestCertify's OPTIONAL third field, or ``None``.

    For a certify it carries ``tpmTPublic``; for a quote it carries the raw
    ``pcrValues``.  ``TcgAttestCertify`` names the field ``tpmTPublic``; the DER
    is positional so the same structure decodes both profiles.
    """
    field = tcg["tpmTPublic"]
    if field is None or not field.hasValue():
        return None
    return bytes(field)


# ---------------------------------------------------------------------------
# VerifierBackend
# ---------------------------------------------------------------------------

class VerifierBackend:
    """Verifies TcgAttest statements (G1 certify or G2 quote)."""

    def __init__(self, oid: str) -> None:
        self._oid = oid

    @classmethod
    def for_oid(cls, oid_str: str) -> "VerifierBackend":
        """Return a backend instance for *oid_str*.

        "2.23.133.20.1" -> G1 (TcgAttestCertify)
        "2.23.133.20.2" -> G2 (TcgAttestQuote)
        """
        if oid_str not in (_OID_TCG_ATTEST_CERTIFY, _OID_TCG_ATTEST_QUOTE):
            raise ValueError(f"Unknown OID: {oid_str}")
        return cls(oid_str)

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def verify(
        self,
        stmt_der: bytes,
        ak_chain: list[bytes],
        *,
        expected_nonce: bytes,
        pcr_selection_der: bytes | None = None,
    ) -> str:
        """Verify a TcgAttest statement, returning only the verdict string.

        Thin wrapper over :meth:`verify_detailed` kept for callers (and tests)
        that only need "affirming" / "contraindicated".
        """
        verdict, _claims = self.verify_detailed(
            stmt_der, ak_chain,
            expected_nonce=expected_nonce,
            pcr_selection_der=pcr_selection_der,
        )
        return verdict

    def verify_detailed(
        self,
        stmt_der: bytes,
        ak_chain: list[bytes],
        *,
        expected_nonce: bytes,
        pcr_selection_der: bytes | None = None,
    ) -> tuple[str, dict | None]:
        """Verify a TcgAttest statement and surface appraised TPM claims.

        Returns ``(verdict, claims)`` where *verdict* is "affirming" or
        "contraindicated" and *claims* is a dict of signature-bound TPM
        measurements (PCR digest, per-PCR values, …) for the quote profile —
        or ``None`` when there is nothing to surface (certify profile, or any
        rejection).  The HTTP service embeds *claims* into the EAR's TPM submod.

        *pcr_selection_der*, when given, is the DER of the
        ``TpmAttestationParams`` the RA/CA broadcast in
        ``NonceResponse.respInfo`` — the quote's ``TPMS_QUOTE_INFO.pcrSelect``
        must cover exactly that PCR set (G_PCR_BIND).
        """
        try:
            return self._verify_inner(
                stmt_der, ak_chain,
                expected_nonce=expected_nonce,
                pcr_selection_der=pcr_selection_der,
            )
        except Exception as exc:  # noqa: BLE001
            logger.warning("VerifierBackend: verification failed: %s", exc)
            return "contraindicated", None

    # ------------------------------------------------------------------
    # Internal
    # ------------------------------------------------------------------

    def _verify_inner(
        self,
        stmt_der: bytes,
        ak_chain: list[bytes],
        *,
        expected_nonce: bytes,
        pcr_selection_der: bytes | None = None,
    ) -> tuple[str, dict | None]:
        # 1. ASN.1-decode the statement (reuse libattest's TcgAttestCertify).
        tcg, _ = asn1_decoder.decode(stmt_der, asn1Spec=TcgAttestCertify())
        tpms_attest_bytes = bytes(tcg["tpmSAttest"])
        signature_field = bytes(tcg["signature"])

        # 2. Magic + attestation type.
        expected_type = (
            _TPM_ST_ATTEST_CERTIFY
            if self._oid == _OID_TCG_ATTEST_CERTIFY
            else _TPM_ST_ATTEST_QUOTE
        )
        if len(tpms_attest_bytes) < 6 or tpms_attest_bytes[:4] != _TPM_GENERATED_VALUE:
            logger.warning("bad TPMS_ATTEST magic")
            return "contraindicated", None
        attest_type = int.from_bytes(tpms_attest_bytes[4:6], "big")
        if attest_type != expected_type:
            logger.warning(
                "wrong attestation type: got %#06x expected %#06x",
                attest_type, expected_type,
            )
            return "contraindicated", None

        # 3. Nonce freshness (extraData == RA-issued nonce). extract_qualifying_data
        #    re-checks the magic and walks the TPM2B fields.
        try:
            tpms_nonce = extract_qualifying_data(tpms_attest_bytes)
        except ValueError as exc:
            logger.warning("could not read qualifyingData: %s", exc)
            return "contraindicated", None
        if tpms_nonce != expected_nonce:
            logger.warning(
                "nonce mismatch: TPMS_ATTEST.extraData=%s expected=%s",
                tpms_nonce.hex(), expected_nonce.hex(),
            )
            return "contraindicated", None

        # 4. Validate the AK certificate chain against the trusted CA (cryptography).
        #    Read the trust anchor fresh each time — the provisioner may write or
        #    replace /tpm-ca/ca_cert.pem after this process started.
        trusted_ca = _load_trusted_ca_cert()
        if trusted_ca is None:
            logger.warning("no usable TRUSTED_CA_CERT_FILE — rejecting")
            return "contraindicated", None
        if not ak_chain:
            logger.warning("no AK certificate in bundle")
            return "contraindicated", None
        try:
            ak_certs = [x509.load_der_x509_certificate(cert) for cert in ak_chain]
            validate_ek_chain(chain=ak_certs, roots=[trusted_ca])
        except (ValueError, InvalidSignature) as exc:
            logger.warning(
                "AK certificate chain validation FAILED: %s: %s",
                type(exc).__name__, exc,
            )
            return "contraindicated", None

        # 5. Verify the AK signature over TPMS_ATTEST (pytss short method).
        try:
            verify_tpm_signature(
                signed_bytes=tpms_attest_bytes,
                tpmt_signature=signature_field,
                public_key=ak_certs[0].public_key(),
            )
        except InvalidSignature:
            logger.warning("AK signature verification FAILED over TPMS_ATTEST")
            return "contraindicated", None
        except (ValueError, RuntimeError) as exc:
            logger.warning("AK signature could not be verified: %s", exc)
            return "contraindicated", None
        logger.info("AK signature over TPMS_ATTEST verified OK")

        # 6. Type-specific checks.
        if self._oid == _OID_TCG_ATTEST_CERTIFY:
            return self._check_certify(tcg, tpms_attest_bytes)
        return self._check_quote(tcg, tpms_attest_bytes, pcr_selection_der)

    def _check_certify(
        self, tcg, tpms_attest_bytes: bytes
    ) -> tuple[str, dict | None]:
        """G1-specific checks: tpmTPublic present, certify name matches."""
        # tpmTPublic must be present.
        tpmt_public = _optional_octets(tcg)
        if tpmt_public is None:
            logger.warning("certify evidence missing tpmTPublic")
            return "contraindicated", None

        # certify.name (from TPMS_CERTIFY_INFO) must equal the name recomputed
        # from the submitted tpmTPublic (reuse libattest's parsers).
        try:
            certify_name = extract_certify_name(tpms_attest_bytes)
            expected_name = compute_tpm_name(tpmt_public)
        except ValueError as exc:
            logger.warning("certify name check failed to parse: %s", exc)
            return "contraindicated", None
        if certify_name != expected_name:
            logger.warning("certify name mismatch (tpmTPublic swap?)")
            return "contraindicated", None

        # Certify carries no PCR state — nothing to surface in the EAT.
        return "affirming", None

    def _check_quote(
        self,
        tcg,
        tpms_attest_bytes: bytes,
        pcr_selection_der: bytes | None = None,
    ) -> tuple[str, dict | None]:
        """G2 checks + appraised PCR claims for the EAT.

        Runs three gates — G_PCR_BIND (quoted set == requested set),
        G_PCR_VALUES_BIND (raw values hash to the signed digest), and G2
        (digest matches the reference baseline) — and, on success, returns the
        signature-bound PCR measurements so the HTTP service can embed them in
        the EAR's TPM submod.
        """
        # Parse the quote's PCR selection + digest (reuse libattest).
        pcr_selections, pcr_digest = extract_quote_info(tpms_attest_bytes)
        if not pcr_selections:
            logger.warning("quote carries no PCR selection")
            return "contraindicated", None
        # This profile expects a single bank; merge indices defensively and use
        # the first bank's algorithm (and log if more than one bank appears).
        if len(pcr_selections) > 1:
            logger.info("quote carries %d PCR banks; merging", len(pcr_selections))
        quoted_pcrs = sorted(
            {idx for sel in pcr_selections for idx in pcr_mask_to_indices(sel["pcr_mask"])}
        )
        quoted_hash_alg = pcr_selections[0]["hash_alg"]

        # G_PCR_BIND: the quoted PCR set must match the RA/CA-selected set
        # from NonceResponse.respInfo (TPM20QuoteRespInfo).
        if pcr_selection_der is not None:
            _req_cert_name, req_pcrs, req_hash_alg = decode_tpm20_quote_resp_info(pcr_selection_der)
            if req_hash_alg is not None and quoted_hash_alg != req_hash_alg:
                logger.warning(
                    "G_PCR_BIND: quoted hash bank %#06x != requested %#06x",
                    quoted_hash_alg, req_hash_alg,
                )
                return "contraindicated", None
            if req_pcrs is not None and quoted_pcrs != sorted(req_pcrs):
                logger.warning(
                    "G_PCR_BIND: quoted PCR set %s != requested %s",
                    quoted_pcrs, sorted(req_pcrs),
                )
                return "contraindicated", None
            if req_pcrs is None and req_hash_alg is None:
                logger.info(
                    "G_PCR_BIND: TPM20QuoteRespInfo carries no pcrs/hashAlgo"
                    " — nothing to compare",
                )
            else:
                logger.info(
                    "G_PCR_BIND: quoted PCR set matches verifier request "
                    "(pcrs=%s, hashAlg=%#06x)", quoted_pcrs, quoted_hash_alg,
                )

        # G_PCR_VALUES_BIND: when the bundle carries the raw per-PCR values
        # (TcgAttestQuote.pcrValues), cryptographically bind them to the signed
        # quote by recomputing pcrDigest = H(values).  The TPM signs only the
        # aggregate digest, never the individual values, so an unbound value
        # list would be attacker-controlled — we MUST NOT surface it until this
        # gate passes.  Absent values are tolerated (digest-only appraisal,
        # back-compat / certify-shaped bundles).
        per_pcr: dict[str, str] | None = None
        pcr_values = _optional_octets(tcg)
        if pcr_values is not None:
            digest_size = _pcr_digest_size(quoted_hash_alg)
            recomputed_digest = _hash_pcr_values(quoted_hash_alg, pcr_values)
            if recomputed_digest != pcr_digest:
                logger.warning(
                    "G_PCR_VALUES_BIND: H(pcrValues)=%s != signed pcrDigest=%s",
                    recomputed_digest.hex(), pcr_digest.hex(),
                )
                return "contraindicated", None
            if len(pcr_values) != len(quoted_pcrs) * digest_size:
                logger.warning(
                    "G_PCR_VALUES_BIND: pcrValues length %d != %d PCRs * %d bytes",
                    len(pcr_values), len(quoted_pcrs), digest_size,
                )
                return "contraindicated", None
            # Map each digest-sized chunk to its PCR index (canonical ascending
            # order — the same order the TPM concatenated to form pcrDigest).
            per_pcr = {
                str(idx): pcr_values[i * digest_size:(i + 1) * digest_size].hex()
                for i, idx in enumerate(quoted_pcrs)
            }
            logger.info(
                "G_PCR_VALUES_BIND: %d PCR value(s) bound to the signed pcrDigest",
                len(quoted_pcrs),
            )

        # G2: PCR appraisal against the reference digest.  Fail-closed: a
        # verifier must never affirm evidence it could not appraise
        # (constraint §2 — no stub verification).
        ref_file = os.environ.get("PCR_REFERENCE_VALUES_FILE")
        if ref_file is None:
            logger.error(
                "G2: PCR appraisal impossible (PCR_REFERENCE_VALUES_FILE unset)"
                " — rejecting evidence",
            )
            return "contraindicated", None

        with open(ref_file) as f:
            ref_data = json.load(f)
        expected_hex = ref_data["expected_pcr_digest_hex"]
        if pcr_digest.hex() != expected_hex:
            logger.warning(
                "G2: PCR appraisal FAILED — pcrDigest=%s expected=%s",
                pcr_digest.hex(), expected_hex,
            )
            return "contraindicated", None

        logger.info("G2: PCR appraisal OK (pcrDigest=%s)", pcr_digest.hex())

        # Build the appraised, signature-bound claims for the EAT.
        claims: dict = {
            "pcr-digest": pcr_digest.hex(),
            "hash-alg": _hash_alg_name(quoted_hash_alg),
            "pcr-selection": quoted_pcrs,
            "pcr-digest-ref-matched": True,
        }
        if per_pcr is not None:
            claims["pcrs"] = per_pcr
            claims["pcr-digest-recomputed"] = True
        return "affirming", claims
