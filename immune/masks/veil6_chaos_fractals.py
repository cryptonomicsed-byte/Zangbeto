#!/usr/bin/env python3
"""Veil 6 — Chaos Fractals: scans Sui Move contracts for reentrancy and state-chaos.

Detects: state mutation before external call (reentrancy pattern), unbounded loops,
potentially recursive calls, raw status integer comparisons (exhaustiveness gap).
Outputs a JSON receipt to immune/receipts/out/veil6_<timestamp>.json.
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
        "rule": "veil6.state_mutation_before_external_call",
        "tag": "CHAOS-REENTRANT",
        "severity": "HIGH",
        # State field written, then within ~500 chars an external emit/transfer
        "pattern": re.compile(
            r"(\w+\.\w+\s*=\s*[^;]+;)[\s\S]{0,500}?(event::emit|transfer::transfer|sui::transfer)",
            re.DOTALL,
        ),
        "description": "State mutation immediately before external call — reentrancy window",
    },
    {
        "rule": "veil6.unbounded_loop",
        "tag": "CHAOS-UNBOUNDED-LOOP",
        "severity": "HIGH",
        # while loop whose condition is not a simple counter comparison
        "pattern": re.compile(
            r"\bwhile\s*\((?!\s*(?:i|j|n|count|idx)\s*[<>])[^)]{10,}\)"
        ),
        "description": "Loop with non-trivial or potentially unbounded condition",
    },
    {
        "rule": "veil6.recursive_function",
        "tag": "CHAOS-RECURSIVE",
        "severity": "MEDIUM",
        "pattern": re.compile(
            r"fun\s+(\w+)\s*\([^)]*\)[^{]*\{[^}]*\b\1\s*\(", re.DOTALL
        ),
        "description": "Function appears to call itself — potential unbounded recursion",
    },
    {
        "rule": "veil6.raw_status_integer",
        "tag": "CHAOS-STATUS-GAP",
        "severity": "MEDIUM",
        "pattern": re.compile(r"status\s*(?:==|!=)\s*\d+u8"),
        "description": "Raw integer status comparison — may miss unhandled enum variants",
    },
]


def _sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    h.update(path.read_bytes())
    return h.hexdigest()


def _scan_file(path: Path) -> list:
    findings = []
    source = path.read_text(encoding="utf-8", errors="replace")
    file_sha = _sha256_file(path)
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
                "sha256": file_sha,
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

    result_state = "contained"
    if any(f["severity"] in ("CRITICAL", "HIGH") for f in all_findings):
        result_state = "exploited"

    receipt = {
        "veil": "veil6_chaos_fractals",
        "timestamp": datetime.datetime.utcnow().isoformat() + "Z",
        "findings_count": len(all_findings),
        "findings": all_findings,
        "result": result_state,
    }

    ts = datetime.datetime.utcnow().strftime("%Y%m%dT%H%M%SZ")
    out_path = RECEIPT_OUT / f"veil6_{ts}.json"
    out_path.write_text(json.dumps(receipt, indent=2))
    print(json.dumps(receipt, indent=2))


if __name__ == "__main__":
    run()
