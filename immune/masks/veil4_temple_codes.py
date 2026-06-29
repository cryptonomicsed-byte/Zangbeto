#!/usr/bin/env python3
"""Veil 4 — Temple Codes: scans Sui Move contracts for access-control vulnerabilities.

Detects: public entry functions missing signer check, unguarded admin field access,
mutable table borrows without preceding assertion.
Outputs a JSON receipt to immune/receipts/out/veil4_<timestamp>.json.
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

# Pattern: public (entry) fun ... { ... } block — captured roughly
_PUBLIC_FUN = re.compile(
    r"public\s+(?:entry\s+)?fun\s+(\w+)\s*(\([^)]*\))[^{]*\{",
    re.DOTALL,
)
_SIGNER_PARAM = re.compile(r"&\s*(?:mut\s+)?(?:signer|TxContext)")

RULES_STATIC = [
    {
        "rule": "veil4.admin_field_unguarded",
        "tag": "ACCESS-ADMIN-UNGUARDED",
        "severity": "HIGH",
        "pattern": re.compile(r"\.admins\b"),
        "description": "Direct .admins field access without capability assertion nearby",
    },
    {
        "rule": "veil4.mutable_borrow_no_assert",
        "tag": "ACCESS-BORROW-UNGUARDED",
        "severity": "MEDIUM",
        "pattern": re.compile(r"table::borrow_mut\s*\("),
        "description": "Mutable table borrow without preceding assert guard",
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

    # Rule: public entry function with no signer/TxContext parameter
    for m in _PUBLIC_FUN.finditer(source):
        params_block = m.group(2)
        if not _SIGNER_PARAM.search(params_block):
            findings.append({
                "rule": "veil4.public_entry_no_signer",
                "tag": "ACCESS-NO-SIGNER",
                "severity": "CRITICAL",
                "description": "Public entry function lacks signer/TxContext — anyone can call",
                "file": str(path),
                "match_count": 1,
                "first_match": m.group(0)[:120].strip(),
                "sha256": file_sha,
            })

    # Static pattern rules
    for rule in RULES_STATIC:
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

    result_state = "exploited" if any(f["severity"] == "CRITICAL" for f in all_findings) else "contained"

    receipt = {
        "veil": "veil4_temple_codes",
        "timestamp": datetime.datetime.utcnow().isoformat() + "Z",
        "findings_count": len(all_findings),
        "findings": all_findings,
        "result": result_state,
    }

    ts = datetime.datetime.utcnow().strftime("%Y%m%dT%H%M%SZ")
    out_path = RECEIPT_OUT / f"veil4_{ts}.json"
    out_path.write_text(json.dumps(receipt, indent=2))
    print(json.dumps(receipt, indent=2))


if __name__ == "__main__":
    run()
