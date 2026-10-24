"""A monorepo report fails with a stale root, then passes an explicit remap."""

import hashlib
import json
import subprocess
import sys
from pathlib import Path

root = Path(__file__).resolve().parents[1]
report = root / "examples/monorepo.sarif"
digest = hashlib.sha256(report.read_bytes()).digest()
command = [
    sys.executable,
    "-I",
    "-m",
    "sarif_sourcecheck",
    str(report),
    "--root",
    str(root / "examples/checkout"),
    "--json",
]
for options, expected in [([], 1), (["--base", "SRCROOT=packages/api"], 0)]:
    result = subprocess.run(command + options, capture_output=True, text=True, check=False)
    assert result.returncode == expected, result.stderr
    data = json.loads(result.stdout)
    assert data["locations_checked"] == 1
    assert data["passed"] == (expected == 0)
    assert "Synthetic demonstration" not in result.stdout
assert hashlib.sha256(report.read_bytes()).digest() == digest
print("Stale root rejected; explicit monorepo remap passed; input unchanged")
