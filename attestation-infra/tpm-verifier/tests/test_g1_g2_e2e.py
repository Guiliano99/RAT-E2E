# SPDX-FileCopyrightText: Copyright 2026 Siemens AG
#
# SPDX-License-Identifier: Apache-2.0

"""End-to-end test of TcgAttestCertifyBackend / TcgAttestQuoteBackend.

Exercises the full verifier path of ``tpm_verifier.py`` using synthetic
TPM evidence built with real RSA crypto (no real TPM required):

    1. Decode TcgAttest* SEQUENCE
    2. Parse TPMS_ATTEST (corrected magic 0xFF544347 = b'\\xffTCG')
    3. Freshness — qualifyingData == session nonce
    4. AK cert chain verified against trusted CA cert
    5. AK RSASSA-SHA256 signature over TPMS_ATTEST
    6. _check_attested:
       - G1 (certify): TPMS_CERTIFY_INFO.name == compute_tpm_name(tpmTPublic)
       - G2 (quote):   pcrDigest == reference (or skipped if no env var)

This is the test that catches a regression like the previous magic-byte
swap, and also catches breakage in the G1 / G2 dispatch.
"""

from __future__ import annotations

import datetime
import hashlib
import os
import struct
import sys
import tempfile
import unittest
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.x509.oid import NameOID
from pyasn1.codec.der import encoder as asn1_encoder
from pyasn1.type import namedtype, univ

# Add the verifier's src directory to sys.path; libattest is imported from the
# installed package (the published dependency on PYTHONPATH inside the
# tpm-verifier image) — no local tmp/ checkout.
HERE = Path(__file__).parent
VERIFIER_SRC = HERE.parent / "src"
sys.path.insert(0, str(VERIFIER_SRC))


_TPM_GENERATED_VALUE = b"\xff\x54\x43\x47"
_TPM_ALG_SHA256 = 0x000B
_TPM_ALG_RSASSA = 0x0014
_TPM_ST_ATTEST_CERTIFY = 0x8017
_TPM_ST_ATTEST_QUOTE = 0x8018


# ── ASN.1 schemas matching gencmpclient's rats_csr_asn.h ──────────────────────

class _TcgAttest(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType("tpmSAttest", univ.OctetString()),
        namedtype.NamedType("signature", univ.OctetString()),
        namedtype.OptionalNamedType("optional", univ.OctetString()),
    )


class _AttestationStatement(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType("type", univ.ObjectIdentifier()),
        namedtype.NamedType("stmt", univ.Any()),
    )


class _AttestationBundle(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType("attestations", univ.SequenceOf(componentType=_AttestationStatement())),
        namedtype.OptionalNamedType("certs", univ.SequenceOf(componentType=univ.Any())),
    )


# ── TPMT_SIGNATURE / TPMS_ATTEST builders ─────────────────────────────────────

def _tpmt_signature_rsassa_sha256(sig_bytes: bytes) -> bytes:
    """Wire-format TPMT_SIGNATURE: sigAlg(2) + hashAlg(2) + size(2) + sig."""
    return (
        struct.pack(">H", _TPM_ALG_RSASSA)
        + struct.pack(">H", _TPM_ALG_SHA256)
        + struct.pack(">H", len(sig_bytes))
        + sig_bytes
    )


def _build_certify_tpms_attest(nonce: bytes, certify_name: bytes) -> bytes:
    qn = b"\x00\x0b" + b"\xee" * 32
    certify_info = (
        struct.pack(">H", len(certify_name)) + certify_name
        + struct.pack(">H", len(qn)) + qn
    )
    return (
        _TPM_GENERATED_VALUE
        + struct.pack(">H", _TPM_ST_ATTEST_CERTIFY)
        + struct.pack(">H", 4) + b"sgnr"
        + struct.pack(">H", len(nonce)) + nonce
        + b"\x00" * 17 + b"\x00" * 8
        + certify_info
    )


def _build_quote_tpms_attest(nonce: bytes, pcr_digest: bytes) -> bytes:
    quote_info = (
        struct.pack(">I", 1)
        + struct.pack(">H", _TPM_ALG_SHA256)
        + b"\x03" + b"\xff\x00\x00"
        + struct.pack(">H", len(pcr_digest)) + pcr_digest
    )
    return (
        _TPM_GENERATED_VALUE
        + struct.pack(">H", _TPM_ST_ATTEST_QUOTE)
        + struct.pack(">H", 4) + b"sgnr"
        + struct.pack(">H", len(nonce)) + nonce
        + b"\x00" * 17 + b"\x00" * 8
        + quote_info
    )


def _make_tpmt_public(payload: bytes = b"\x00" * 60) -> bytes:
    """Synthetic TPMT_PUBLIC: type(2) + nameAlg(2=SHA256) + payload."""
    return struct.pack(">HH", 0x0001, _TPM_ALG_SHA256) + payload


# ── PKI test fixtures ─────────────────────────────────────────────────────────

def _make_ak_cert_chain() -> tuple[bytes, rsa.RSAPrivateKey, bytes]:
    """Produce (ca_cert_pem, ak_private_key, ak_cert_der)."""
    # CA
    ca_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    ca_subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "test-ca")])
    ca_cert = (
        x509.CertificateBuilder()
        .subject_name(ca_subject)
        .issuer_name(ca_subject)
        .public_key(ca_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.datetime.now(datetime.timezone.utc))
        .not_valid_after(datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=365))
        .sign(ca_key, hashes.SHA256())
    )
    # AK (signed by CA)
    ak_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    ak_subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "test-ak")])
    ak_cert = (
        x509.CertificateBuilder()
        .subject_name(ak_subject)
        .issuer_name(ca_subject)
        .public_key(ak_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.datetime.now(datetime.timezone.utc))
        .not_valid_after(datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=365))
        .sign(ca_key, hashes.SHA256())
    )
    return (
        ca_cert.public_bytes(serialization.Encoding.PEM),
        ak_key,
        ak_cert.public_bytes(serialization.Encoding.DER),
    )


def _sign_tpms_attest(ak_key: rsa.RSAPrivateKey, tpms_attest: bytes) -> bytes:
    """Sign TPMS_ATTEST with the AK using RSASSA-PKCS1v15 + SHA256."""
    return ak_key.sign(tpms_attest, padding.PKCS1v15(), hashes.SHA256())


def _build_tcg_attest_certify(
    tpms_attest: bytes,
    sig: bytes,
    tpmt_public: bytes | None,
) -> bytes:
    tcg = _TcgAttest()
    tcg["tpmSAttest"] = tpms_attest
    tcg["signature"] = _tpmt_signature_rsassa_sha256(sig)
    if tpmt_public is not None:
        tcg["optional"] = tpmt_public
    return asn1_encoder.encode(tcg)


# ── Test cases ────────────────────────────────────────────────────────────────

class TpmVerifierE2ETest(unittest.TestCase):
    """Drive the registered backends end-to-end with synthetic-but-real evidence."""

    @classmethod
    def setUpClass(cls) -> None:
        # Write CA pem to a tempfile and point TRUSTED_CA_CERT_FILE at it
        # before importing tpm_verifier (the env var is read at module load).
        ca_pem, ak_key, ak_cert_der = _make_ak_cert_chain()
        cls._tmp = tempfile.NamedTemporaryFile(delete=False, suffix=".pem")
        cls._tmp.write(ca_pem)
        cls._tmp.flush()
        cls._tmp.close()
        os.environ["TRUSTED_CA_CERT_FILE"] = cls._tmp.name
        os.environ.pop("USE_WRONG_CA", None)
        os.environ.pop("PCR_REFERENCE_VALUES_FILE", None)

        cls.ak_key = ak_key
        cls.ak_cert_der = ak_cert_der

        # Force-reload tpm_verifier so the new env var is picked up
        if "tpm_verifier" in sys.modules:
            del sys.modules["tpm_verifier"]
        import tpm_verifier  # noqa: PLC0415
        cls.tpm_verifier = tpm_verifier

    @classmethod
    def tearDownClass(cls) -> None:
        os.unlink(cls._tmp.name)

    # ── G1: certify backend ───────────────────────────────────────────────────

    def test_g1_happy_path_returns_affirming(self) -> None:
        from libattest.formats.tpm.tpm_name import compute_tpm_name

        nonce = b"\x42" * 32
        tpmt_public = _make_tpmt_public(b"\x77" * 60)
        tpms_attest = _build_certify_tpms_attest(nonce, compute_tpm_name(tpmt_public))
        sig = _sign_tpms_attest(self.ak_key, tpms_attest)
        stmt = _build_tcg_attest_certify(tpms_attest, sig, tpmt_public)

        backend = self.tpm_verifier.VerifierBackend.for_oid("2.23.133.20.1")
        verdict = backend.verify(stmt, [self.ak_cert_der], expected_nonce=nonce)

        self.assertEqual(verdict, "affirming")

    def test_g1_swap_attack_returns_contraindicated(self) -> None:
        """Audit attack: TPM signed evidence for X but bundle has Y as tpmTPublic."""
        from libattest.formats.tpm.tpm_name import compute_tpm_name

        nonce = b"\xa1" * 32
        tpmt_x = _make_tpmt_public(b"\x11" * 60)
        tpmt_y = _make_tpmt_public(b"\x22" * 60)
        # certify.name == H(X), but attacker submits tpmTPublic = Y
        tpms_attest = _build_certify_tpms_attest(nonce, compute_tpm_name(tpmt_x))
        sig = _sign_tpms_attest(self.ak_key, tpms_attest)
        stmt = _build_tcg_attest_certify(tpms_attest, sig, tpmt_y)

        backend = self.tpm_verifier.VerifierBackend.for_oid("2.23.133.20.1")
        verdict = backend.verify(stmt, [self.ak_cert_der], expected_nonce=nonce)

        self.assertEqual(verdict, "contraindicated")

    def test_g1_missing_tpmt_public_returns_contraindicated(self) -> None:
        from libattest.formats.tpm.tpm_name import compute_tpm_name

        nonce = b"\xb2" * 32
        tpmt_public = _make_tpmt_public()
        tpms_attest = _build_certify_tpms_attest(nonce, compute_tpm_name(tpmt_public))
        sig = _sign_tpms_attest(self.ak_key, tpms_attest)
        stmt = _build_tcg_attest_certify(tpms_attest, sig, tpmt_public=None)

        backend = self.tpm_verifier.VerifierBackend.for_oid("2.23.133.20.1")
        verdict = backend.verify(stmt, [self.ak_cert_der], expected_nonce=nonce)

        self.assertEqual(verdict, "contraindicated")

    def test_nonce_freshness_failure_returns_contraindicated(self) -> None:
        from libattest.formats.tpm.tpm_name import compute_tpm_name

        tpmt_public = _make_tpmt_public()
        tpms_attest = _build_certify_tpms_attest(b"old-nonce" * 4, compute_tpm_name(tpmt_public))
        sig = _sign_tpms_attest(self.ak_key, tpms_attest)
        stmt = _build_tcg_attest_certify(tpms_attest, sig, tpmt_public)

        backend = self.tpm_verifier.VerifierBackend.for_oid("2.23.133.20.1")
        verdict = backend.verify(stmt, [self.ak_cert_der], expected_nonce=b"different-nonce" * 2)

        self.assertEqual(verdict, "contraindicated")

    def test_bad_signature_returns_contraindicated(self) -> None:
        """The -bad_attest_sig negative path: corrupt one byte → AK verify fails."""
        from libattest.formats.tpm.tpm_name import compute_tpm_name

        nonce = b"\xc3" * 32
        tpmt_public = _make_tpmt_public()
        tpms_attest = _build_certify_tpms_attest(nonce, compute_tpm_name(tpmt_public))
        sig = bytearray(_sign_tpms_attest(self.ak_key, tpms_attest))
        sig[0] ^= 0x01  # corrupt one bit
        stmt = _build_tcg_attest_certify(tpms_attest, bytes(sig), tpmt_public)

        backend = self.tpm_verifier.VerifierBackend.for_oid("2.23.133.20.1")
        verdict = backend.verify(stmt, [self.ak_cert_der], expected_nonce=nonce)

        self.assertEqual(verdict, "contraindicated")

    # ── G2: quote backend ─────────────────────────────────────────────────────

    def test_g2_no_reference_file_fails_closed(self) -> None:
        os.environ.pop("PCR_REFERENCE_VALUES_FILE", None)
        nonce = b"\xd4" * 32
        digest = hashlib.sha256(b"some-platform-state").digest()
        tpms_attest = _build_quote_tpms_attest(nonce, digest)
        sig = _sign_tpms_attest(self.ak_key, tpms_attest)
        # TPMS_ATTEST type=0x8018 (QUOTE); tpmTPublic is irrelevant for quotes
        tcg = _TcgAttest()
        tcg["tpmSAttest"] = tpms_attest
        tcg["signature"] = _tpmt_signature_rsassa_sha256(sig)
        stmt = asn1_encoder.encode(tcg)

        backend = self.tpm_verifier.VerifierBackend.for_oid("2.23.133.20.2")
        verdict = backend.verify(stmt, [self.ak_cert_der], expected_nonce=nonce)

        # Fail-closed: evidence that cannot be appraised must be rejected
        # (constraint §2 — no stub verification).
        self.assertEqual(verdict, "contraindicated")

    def test_g2_with_matching_reference_file_returns_affirming(self) -> None:
        nonce = b"\xe5" * 32
        digest = hashlib.sha256(b"golden-platform").digest()

        # Write a reference values JSON file
        ref = tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False)
        try:
            import json
            json.dump({"description": "test", "expected_pcr_digest_hex": digest.hex()}, ref)
            ref.close()
            os.environ["PCR_REFERENCE_VALUES_FILE"] = ref.name

            tpms_attest = _build_quote_tpms_attest(nonce, digest)
            sig = _sign_tpms_attest(self.ak_key, tpms_attest)
            tcg = _TcgAttest()
            tcg["tpmSAttest"] = tpms_attest
            tcg["signature"] = _tpmt_signature_rsassa_sha256(sig)
            stmt = asn1_encoder.encode(tcg)

            backend = self.tpm_verifier.VerifierBackend.for_oid("2.23.133.20.2")
            verdict = backend.verify(stmt, [self.ak_cert_der], expected_nonce=nonce)

            self.assertEqual(verdict, "affirming")
        finally:
            os.unlink(ref.name)
            os.environ.pop("PCR_REFERENCE_VALUES_FILE", None)

    def test_g2_with_mismatching_reference_file_returns_contraindicated(self) -> None:
        nonce = b"\xf6" * 32
        actual_digest = hashlib.sha256(b"compromised").digest()
        expected_digest = hashlib.sha256(b"golden").digest()

        ref = tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False)
        try:
            import json
            json.dump({"expected_pcr_digest_hex": expected_digest.hex()}, ref)
            ref.close()
            os.environ["PCR_REFERENCE_VALUES_FILE"] = ref.name

            tpms_attest = _build_quote_tpms_attest(nonce, actual_digest)
            sig = _sign_tpms_attest(self.ak_key, tpms_attest)
            tcg = _TcgAttest()
            tcg["tpmSAttest"] = tpms_attest
            tcg["signature"] = _tpmt_signature_rsassa_sha256(sig)
            stmt = asn1_encoder.encode(tcg)

            backend = self.tpm_verifier.VerifierBackend.for_oid("2.23.133.20.2")
            verdict = backend.verify(stmt, [self.ak_cert_der], expected_nonce=nonce)

            self.assertEqual(verdict, "contraindicated")
        finally:
            os.unlink(ref.name)
            os.environ.pop("PCR_REFERENCE_VALUES_FILE", None)

    # ── G_PCR_VALUES_BIND: raw per-PCR values carried in pcrValues ────────────

    def test_g2_bound_pcr_values_affirm_with_per_pcr_claims(self) -> None:
        """pcrValues that hash to the signed pcrDigest are surfaced as claims."""
        nonce = b"\x5a" * 32
        # The quote builder's \xff bitmap selects PCRs 0..7 (8 registers).
        pcr_vals = [bytes([i]) * 32 for i in range(8)]
        concat = b"".join(pcr_vals)
        digest = hashlib.sha256(concat).digest()

        ref = tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False)
        try:
            import json
            json.dump({"expected_pcr_digest_hex": digest.hex()}, ref)
            ref.close()
            os.environ["PCR_REFERENCE_VALUES_FILE"] = ref.name

            tpms_attest = _build_quote_tpms_attest(nonce, digest)
            sig = _sign_tpms_attest(self.ak_key, tpms_attest)
            tcg = _TcgAttest()
            tcg["tpmSAttest"] = tpms_attest
            tcg["signature"] = _tpmt_signature_rsassa_sha256(sig)
            tcg["optional"] = concat  # pcrValues
            stmt = asn1_encoder.encode(tcg)

            backend = self.tpm_verifier.VerifierBackend.for_oid("2.23.133.20.2")
            verdict, claims = backend.verify_detailed(
                stmt, [self.ak_cert_der], expected_nonce=nonce
            )

            self.assertEqual(verdict, "affirming")
            self.assertIsNotNone(claims)
            self.assertEqual(claims["pcr-digest"], digest.hex())
            self.assertEqual(claims["hash-alg"], "sha256")
            self.assertTrue(claims["pcr-digest-recomputed"])
            self.assertTrue(claims["pcr-digest-ref-matched"])
            self.assertEqual(sorted(int(k) for k in claims["pcrs"]), list(range(8)))
            self.assertEqual(claims["pcrs"]["0"], (b"\x00" * 32).hex())
            self.assertEqual(claims["pcrs"]["7"], (b"\x07" * 32).hex())
        finally:
            os.unlink(ref.name)
            os.environ.pop("PCR_REFERENCE_VALUES_FILE", None)

    def test_g2_tampered_pcr_values_return_contraindicated(self) -> None:
        """A swapped PCR value can't be re-signed → H(values)!=pcrDigest → reject.

        This is the security crux of the per-PCR-value EAT: the TPM signs only
        the aggregate digest, so the verifier MUST recompute it from the raw
        values before trusting (and later attesting) them.
        """
        nonce = b"\x6b" * 32
        concat = b"".join(bytes([i]) * 32 for i in range(8))
        digest = hashlib.sha256(concat).digest()  # signed digest commits to real values

        ref = tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False)
        try:
            import json
            json.dump({"expected_pcr_digest_hex": digest.hex()}, ref)
            ref.close()
            os.environ["PCR_REFERENCE_VALUES_FILE"] = ref.name

            tpms_attest = _build_quote_tpms_attest(nonce, digest)
            sig = _sign_tpms_attest(self.ak_key, tpms_attest)
            tampered = bytearray(concat)
            tampered[0] ^= 0xFF  # forge one PCR value; cannot re-sign the quote
            tcg = _TcgAttest()
            tcg["tpmSAttest"] = tpms_attest
            tcg["signature"] = _tpmt_signature_rsassa_sha256(sig)
            tcg["optional"] = bytes(tampered)
            stmt = asn1_encoder.encode(tcg)

            backend = self.tpm_verifier.VerifierBackend.for_oid("2.23.133.20.2")
            verdict, claims = backend.verify_detailed(
                stmt, [self.ak_cert_der], expected_nonce=nonce
            )

            self.assertEqual(verdict, "contraindicated")
            self.assertIsNone(claims)
        finally:
            os.unlink(ref.name)
            os.environ.pop("PCR_REFERENCE_VALUES_FILE", None)

    def test_g2_absent_pcr_values_affirm_with_digest_only_claims(self) -> None:
        """Back-compat: no pcrValues → affirm via digest, no per-PCR claims."""
        nonce = b"\x7c" * 32
        digest = hashlib.sha256(b"golden-no-values").digest()

        ref = tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False)
        try:
            import json
            json.dump({"expected_pcr_digest_hex": digest.hex()}, ref)
            ref.close()
            os.environ["PCR_REFERENCE_VALUES_FILE"] = ref.name

            tpms_attest = _build_quote_tpms_attest(nonce, digest)
            sig = _sign_tpms_attest(self.ak_key, tpms_attest)
            tcg = _TcgAttest()
            tcg["tpmSAttest"] = tpms_attest
            tcg["signature"] = _tpmt_signature_rsassa_sha256(sig)
            stmt = asn1_encoder.encode(tcg)

            backend = self.tpm_verifier.VerifierBackend.for_oid("2.23.133.20.2")
            verdict, claims = backend.verify_detailed(
                stmt, [self.ak_cert_der], expected_nonce=nonce
            )

            self.assertEqual(verdict, "affirming")
            self.assertIsNotNone(claims)
            self.assertEqual(claims["pcr-digest"], digest.hex())
            self.assertNotIn("pcrs", claims)
        finally:
            os.unlink(ref.name)
            os.environ.pop("PCR_REFERENCE_VALUES_FILE", None)


if __name__ == "__main__":
    unittest.main()
