#!/usr/bin/env python3
"""Converteste raportarile Outlook .msg in .eml, la pregatirea corpusului.

Conversia propriu-zisa sta in `triage.msg_convert`, ca sa fie exact aceeasi si
cand cineva arunca un .msg direct in dashboard. Aici e doar interfata de linie
de comanda.

Dependinta (doar pentru pregatirea corpusului, nu pentru runtime):
    pip install -r requirements-corpus.txt

Utilizare:
    python3 scripts/msg_to_eml.py corpus/msg/1.msg -o corpus/eml/01_cyberready_forward.eml
    python3 scripts/msg_to_eml.py corpus/msg/*.msg --outdir corpus/eml/
    python3 scripts/msg_to_eml.py corpus/msg/1.msg --stdout | head -40
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from triage.msg_convert import MsgConversionUnavailable, convert_file
from triage.secure_files import save_secure_file


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("inputs", nargs="+", type=Path, help="fisiere .msg")
    ap.add_argument("-o", "--output", type=Path, help="fisier .eml de iesire (o singura intrare)")
    ap.add_argument("--outdir", type=Path, help="director de iesire, pastreaza numele")
    ap.add_argument("--stdout", action="store_true", help="scrie la stdout")
    args = ap.parse_args()

    if args.output and len(args.inputs) > 1:
        ap.error("--output merge doar cu o singura intrare; foloseste --outdir")

    for src in args.inputs:
        try:
            raw = convert_file(src)
        except MsgConversionUnavailable as err:
            return int(bool(sys.stderr.write(f"{err}\n"))) or 1

        if args.stdout:
            sys.stdout.buffer.write(raw)
            continue
        if args.output:
            dst = args.output
        elif args.outdir:
            dst = args.outdir / (src.stem + ".eml")
        else:
            dst = src.with_suffix(".eml")

        # Salvare securizata cu permisiuni 0o600 (sectiunea 4.5).
        save_secure_file(dst, raw)
        print(f"{src} -> {dst}  ({len(raw)} octeti)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
