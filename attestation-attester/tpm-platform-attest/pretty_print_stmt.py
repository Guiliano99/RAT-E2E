#!/usr/bin/env python3
# SPDX-FileCopyrightText: Copyright 2026 Siemens AG
# SPDX-License-Identifier: Apache-2.0

"""Auto-detect and pretty-print CMP genm/genp PKIMessage DER files.

Thin front-end over libattest's official CMP PKIMessage CLI: it uses
``libattest.formats.csrattest.pretty_print_cmp_stmt.parse_pkimessage`` to
auto-detect a ``genm`` (NonceRequest) or ``genp`` (NonceResponse), decode the
inner ``reqInfo``/``respInfo`` via the ``libattest.formats.stmt_mappings``
structure registry, and print the fully decoded structure. Demo-agnostic and
dependency-free beyond what libattest already needs (pyasn1 / pyasn1_alt_modules).

Usage: pretty_print_stmt.py req1-genm.der rsp1-genp.der
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from libattest.formats.csrattest.pretty_print_cmp_stmt import parse_pkimessage


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    """Parse one or more PKIMessage DER file paths."""
    parser = argparse.ArgumentParser(
        description="Pretty-print one or more CMP genm/genp PKIMessage DER files (auto-detected).",
        epilog="Example: %(prog)s req1-genm.der rsp1-genp.der",
    )
    parser.add_argument("files", type=Path, nargs="+", help="DER-encoded PKIMessage file(s).")
    return parser.parse_args(argv)


def main(args: argparse.Namespace) -> int:
    """Load, auto-dispatch, decode, and print each given PKIMessage DER file."""
    for path in args.files:
        try:
            pkimessage = parse_pkimessage(path.read_bytes())
        except (OSError, ValueError) as exc:
            sys.stderr.write(f"error: {path}: {exc}\n")
            return 2

        body_name = pkimessage["body"].getName()
        message = pkimessage["body"][body_name][0]["infoValue"]
        sys.stdout.write(f"{message.prettyPrint()}\n\n")

    return 0


if __name__ == "__main__":
    sys.exit(main(parse_args()))
