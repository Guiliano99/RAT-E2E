# SPDX-FileCopyrightText: Copyright 2026 Siemens AG
#
# SPDX-License-Identifier: Apache-2.0

"""Regression test for the verifier_service evidence-OID allow-list.

The platform-attestation profile must appraise only TcgAttestQuote
(2.23.133.20.2).  Honouring a client-chosen TcgAttestCertify OID
(2.23.133.20.1) would dispatch to a backend that performs no PCR appraisal
and hand back an affirming verdict for an unappraised platform — an
attestation bypass.  The allow-list short-circuits to a contraindicated EAR
before any backend is selected.
"""

from __future__ import annotations

import base64
import importlib.util
import json
import os
import sys
import unittest
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric import ec

HERE = Path(__file__).parent
# libattest-py must be importable (verifier_service imports tpm_verifier which
# pulls in libattest), but we load verifier_service itself from its EXPLICIT
# path below — a stale duplicate lives at tmp/libattest-py/src/verifier_service.py
# and a bare `import verifier_service` would resolve by sys.path order alone.
sys.path.insert(0, str(HERE.parent.parent.parent / "tmp" / "libattest-py" / "src"))
sys.path.insert(0, str(HERE.parent / "src"))

_SVC_PATH = HERE.parent / "src" / "verifier_service.py"


def _load_verifier_service():
    """Load the verifier's own verifier_service.py by absolute path.

    Importing by name is unsafe here: tmp/libattest-py/src/verifier_service.py
    is a stale copy without the OID gate, and would shadow this module if it
    came first on sys.path. Loading from the explicit path removes the ambiguity.
    """
    spec = importlib.util.spec_from_file_location("verifier_service_under_test", _SVC_PATH)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def _ear_status(jwt: str) -> str:
    payload_b64 = jwt.split(".")[1]
    payload_b64 += "=" * (-len(payload_b64) % 4)
    payload = json.loads(base64.urlsafe_b64decode(payload_b64))
    return payload["submods"]["TPM"]["ear.status"]


class OidAllowListTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        os.environ.pop("VERIFIER_ALLOWED_OIDS", None)
        cls.svc = _load_verifier_service()
        # Confirm we loaded the gated module, not the stale duplicate.
        assert hasattr(cls.svc, "_allowed_oids"), (
            f"loaded wrong verifier_service (no OID gate): {cls.svc.__file__}"
        )
        # _sign_ear_jwt needs a module signing key; inject an ephemeral one.
        cls.svc._SIGNING_KEY = ec.generate_private_key(ec.SECP256R1())

    def _submit(self, oid: str) -> tuple[int, dict]:
        body = {
            "nonce": base64.b64encode(b"\x00" * 32).decode(),
            # An empty bundle is fine: the allow-list check for a disallowed
            # OID runs before any DER parsing, so the body never reaches it.
            "evidence": base64.b64encode(b"\x30\x00").decode(),
            "oid": oid,
        }
        return self.svc._verify_submission(body)

    def test_default_allows_only_quote_oid(self) -> None:
        self.assertEqual(self.svc._allowed_oids(), frozenset({"2.23.133.20.2"}))

    def test_certify_oid_is_rejected_at_the_gate(self) -> None:
        # The gate emits a "refusing evidence OID" warning ONLY when it rejects;
        # asserting it fires distinguishes a gate rejection from a later
        # appraisal failure (both end in a contraindicated EAR).
        with self.assertLogs("verifier_service", level="WARNING") as cm:
            status, resp = self._submit("2.23.133.20.1")
        self.assertEqual(status, 200)
        self.assertEqual(_ear_status(resp["ear"]), "contraindicated")
        self.assertTrue(
            any("refusing evidence OID 2.23.133.20.1" in m for m in cm.output),
            f"gate did not log a refusal for the certify OID: {cm.output}",
        )

    def test_quote_oid_passes_the_gate(self) -> None:
        # The quote OID is allowed, so the gate must NOT emit its refusal
        # warning; the contraindicated verdict here comes from the later
        # (empty-bundle) appraisal path, proving the gate let the OID through.
        with self.assertLogs("verifier_service", level="INFO") as cm:
            status, resp = self._submit("2.23.133.20.2")
        self.assertEqual(status, 200)
        self.assertEqual(_ear_status(resp["ear"]), "contraindicated")
        self.assertFalse(
            any("refusing evidence OID" in m for m in cm.output),
            f"quote OID was wrongly rejected at the gate: {cm.output}",
        )

    def test_env_override_extends_allowlist(self) -> None:
        os.environ["VERIFIER_ALLOWED_OIDS"] = "2.23.133.20.1,2.23.133.20.2"
        try:
            self.assertEqual(
                self.svc._allowed_oids(),
                frozenset({"2.23.133.20.1", "2.23.133.20.2"}),
            )
        finally:
            os.environ.pop("VERIFIER_ALLOWED_OIDS", None)


if __name__ == "__main__":
    unittest.main()
