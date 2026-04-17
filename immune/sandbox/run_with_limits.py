#!/usr/bin/env python3
"""Sandbox wrapper: runs a subprocess under CPU and memory resource limits."""

import sys
import resource
import subprocess

CPU_LIMIT_SECONDS = 30
MEMORY_LIMIT_BYTES = 256 * 1024 * 1024  # 256 MB


def _apply_limits():
    resource.setrlimit(resource.RLIMIT_CPU, (CPU_LIMIT_SECONDS, CPU_LIMIT_SECONDS))
    resource.setrlimit(resource.RLIMIT_AS, (MEMORY_LIMIT_BYTES, MEMORY_LIMIT_BYTES))


def main():
    if len(sys.argv) < 2:
        print("usage: run_with_limits.py <command> [args...]", file=sys.stderr)
        sys.exit(1)

    cmd = sys.argv[1:]
    result = subprocess.run(cmd, preexec_fn=_apply_limits)
    sys.exit(result.returncode)


if __name__ == "__main__":
    main()
