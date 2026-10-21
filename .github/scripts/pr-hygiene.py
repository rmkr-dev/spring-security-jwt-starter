#!/usr/bin/env python3
"""Fail the build on repository problems that tests do not catch.

Scans tracked-looking source, skipping build output. Intended for pull requests.
"""
import os
import re
import sys

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
SKIP_DIRS = {".git", "target", "node_modules", ".idea", ".m2"}

WILDCARD_IMPORT = re.compile(r"^\s*import\s+(?:static\s+)?[\w.]+\.\*\s*;")
PRIVATE_KEY = re.compile(r"-----BEGIN (?:RSA |ENCRYPTED )?PRIVATE KEY-----")
AWS_KEY = re.compile(r"\bAKIA[0-9A-Z]{16}\b")
PRINT_STACK = re.compile(r"\bprintStackTrace\s*\(")

problems = []


def rel(path):
    return os.path.relpath(path, ROOT)


def walk():
    for dirpath, dirnames, filenames in os.walk(ROOT):
        dirnames[:] = [name for name in dirnames if name not in SKIP_DIRS]
        for name in filenames:
            yield os.path.join(dirpath, name)


for path in walk():
    relative = rel(path).replace(os.sep, "/")
    if relative.startswith("target/") or "/target/" in relative:
        problems.append(f"{relative}: build output is in the tree that CI scans")
        continue
    if relative.startswith(".github/workflows/") and relative.endswith((".yml", ".yaml")):
        with open(path, encoding="utf-8") as handle:
            text = handle.read()
        if "pull_request_target:" in text:
            problems.append(f"{relative}: pull_request_target runs untrusted PR code with this repo's secrets")
    if not relative.endswith(".java"):
        continue
    main = "/src/main/" in f"/{relative}"
    with open(path, encoding="utf-8") as handle:
        lines = handle.readlines()
    for number, line in enumerate(lines, start=1):
        if main and WILDCARD_IMPORT.match(line):
            problems.append(f"{relative}:{number}: wildcard import")
        if main and PRINT_STACK.search(line):
            problems.append(f"{relative}:{number}: printStackTrace")
        if main and PRIVATE_KEY.search(line):
            problems.append(f"{relative}:{number}: private key material under src/main")
        if AWS_KEY.search(line):
            problems.append(f"{relative}:{number}: AWS access key id")

if problems:
    print("PR hygiene failed:", file=sys.stderr)
    for problem in problems:
        print(f"  {problem}", file=sys.stderr)
    sys.exit(1)

print("PR hygiene passed")
