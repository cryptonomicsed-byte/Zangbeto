#!/usr/bin/env python3
"""Veil 1 — Ifa Bones: scans Sui Move contracts for arithmetic vulnerabilities.

Detects: unchecked u64 arithmetic, division-by-zero risk, unguarded arithmetic results.
Outputs a JSON receipt to immune/receipts/out/veil1_<timestamp>.json.
"""

import re
import json
import hashlib
import datetime
from pathlib import Path

SHRINE_DIRS = [
    Path(__file__).parent.parent.parent / "shrine" / "sources",
    Path(__file__).parent.parent.parent / "shrine" / "examples",
]

RECEIPT_OUT = Path(__file__).parent.parent / "receipts" / "out"

RULES = [
    {
        "rule": "veil1.unchecked_u64_arithmetic",
        "tag": "ARITH-OVERFLOW",
        "severity": "HIGH",
        "pattern": re.compile(r"\bu64\b[^;]*?[\+\-\*]", re.DOTALL),
        "description": "Unchecked u64 arithmetic — potential overflow/underflow",
    },
    {
        "rule": "veil1.division_without_zero_guard",
        "tag": "DIV-ZERO",
        "severity": "HIGH",
        "pattern": re.compile(r"let\s+\w+\s*=\s*[^;]*?/[^/\*][^;]*?;"),
        "description": "Division operation without preceding zero-check guard",
    },
    {
        "rule": "veil1.arithmetic_result_unasserted",
        "tag": "ARITH-NO-ASSERT",
        "severity": "MEDIUM",
        "pattern": re.compile(r"let\s+\w+\s*=\s*\w+\s*[\+\-\*]\s*\w+"),
        "description": "Arithmetic result stored without assertion guard",
    },
]


def _sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    h.update(path.read_bytes())
    return h.hexdigest()


def _scan_file(path: Path) -> list:
    findings = []
    source = path.read_text(encoding="utf-8", errors="replace")
    for rule in RULES:
        matches = list(rule["pattern"].finditer(source))
        if matches:
            findings.append({
                "rule": rule["rule"],
                "tag": rule["tag"],
                "severity": rule["severity"],
                "description": rule["description"],
                "file": str(path),
                "match_count": len(matches),
                "first_match": matches[0].group(0)[:120].strip(),
                "sha256": _sha256_file(path),
            })
    return findings


def run():
    RECEIPT_OUT.mkdir(parents=True, exist_ok=True)
    all_findings = []

    for shrine_dir in SHRINE_DIRS:
        if not shrine_dir.exists():
            continue
        for move_file in sorted(shrine_dir.rglob("*.move")):
            all_findings.extend(_scan_file(move_file))

    severity_rank = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
    result_state = "contained"
    if any(f["severity"] in ("CRITICAL", "HIGH") for f in all_findings):
        result_state = "exploited"

    receipt = {
        "veil": "veil1_ifa_bones",
        "timestamp": datetime.datetime.utcnow().isoformat() + "Z",
        "findings_count": len(all_findings),
        "findings": sorted(all_findings, key=lambda f: severity_rank.get(f["severity"], 9)),
        "result": result_state,
    }

    ts = datetime.datetime.utcnow().strftime("%Y%m%dT%H%M%SZ")
    out_path = RECEIPT_OUT / f"veil1_{ts}.json"
    out_path.write_text(json.dumps(receipt, indent=2))
    print(json.dumps(receipt, indent=2))


if __name__ == "__main__":
    run()
