import json
import hashlib
import sys
from dataclasses import dataclass, asdict
from enum import IntEnum
from typing import Optional


class Severity(IntEnum):
    INFO = 0
    WARNING = 1
    ERROR = 2


class Category(IntEnum):
    TYPE = 1
    LOGIC = 2
    SECURITY = 4
    RECEIPT = 8
    IDENTITY = 16
    RHYTHM = 32


@dataclass
class Diagnostic:
    version: str = "1.0"
    language: str = "python"
    package: str = ""
    file: str = ""
    line: int = 0
    column: int = 0
    code: str = ""
    severity: Severity = Severity.ERROR
    category: Category = Category.LOGIC
    message: str = ""
    agent_id: str = ""
    birth_timestamp: int = 0
    tier: str = "apprentice"
    sabbath_active: bool = False
    repair_id: str = ""
    repair_strategy: str = "manual"

    def to_dict(self) -> dict:
        return {
            "version": self.version,
            "source": {
                "language": self.language,
                "package": self.package,
                "file": self.file,
                "line": self.line,
                "column": self.column,
            },
            "diagnostic": {
                "code": self.code,
                "severity": self.severity.name.lower(),
                "category": self.category.name.lower(),
                "message": self.message,
                "context": {
                    "agent_id": self.agent_id,
                    "birth_timestamp": self.birth_timestamp,
                    "tier": self.tier,
                    "sabbath_active": self.sabbath_active,
                }
            },
            "repair": {
                "id": self.repair_id,
                "strategy": self.repair_strategy,
            } if self.repair_id else None,
            "audit_trail": {
                "zangbeto_verified": False,
                "timestamp": __import__('time').strftime("%Y-%m-%dT%H:%M:%SZ", __import__('time').gmtime()),
            }
        }

    def emit(self) -> str:
        payload = self.to_dict()
        print(json.dumps(payload), file=sys.stderr, flush=True)
        return json.dumps(payload)


def hash_message(message: str) -> str:
    return hashlib.sha256(message.encode()).hexdigest()


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="Emit diagnostic in OMO format")
    parser.add_argument("--package", default="")
    parser.add_argument("--file", default="")
    parser.add_argument("--line", type=int, default=0)
    parser.add_argument("--code", default="")
    parser.add_argument("--severity", default="error")
    parser.add_argument("--category", default="logic")
    parser.add_argument("--message", default="")
    parser.add_argument("--agent-id", default="")
    parser.add_argument("--repair-id", default="")
    parser.add_argument("--repair-strategy", default="manual")
    args = parser.parse_args()

    d = Diagnostic(
        package=args.package,
        file=args.file,
        line=args.line,
        code=args.code,
        severity=Severity[args.severity.upper()] if args.severity.upper() in Severity.__members__ else Severity.ERROR,
        category=Category[args.category.upper()] if args.category.upper() in Category.__members__ else Category.LOGIC,
        message=args.message,
        agent_id=args.agent_id,
        repair_id=args.repair_id,
        repair_strategy=args.repair_strategy,
    )
    d.emit()