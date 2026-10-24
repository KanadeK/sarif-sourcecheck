"""Install the built wheel in a new venv and run from outside the checkout."""

import os
import subprocess
import tempfile
import venv
from pathlib import Path

root = Path(__file__).resolve().parents[1]
wheels = list((root / "dist").glob("*.whl"))
if len(wheels) != 1:
    raise SystemExit("Build exactly one wheel first: python -m build")
environment = dict(os.environ)
environment.pop("PYTHONPATH", None)
with tempfile.TemporaryDirectory(prefix="sarif-sourcecheck-install-") as folder:
    base = Path(folder)
    venv.EnvBuilder(with_pip=True).create(base / "venv")
    python = base / "venv" / ("Scripts/python.exe" if os.name == "nt" else "bin/python")
    subprocess.run(
        [str(python), "-I", "-m", "pip", "install", "--no-index", "--no-deps", str(wheels[0])],
        check=True,
        cwd=base,
        env=environment,
    )
    subprocess.run(
        [str(python), "-I", "-m", "sarif_sourcecheck", "--version"],
        check=True,
        cwd=base,
        env=environment,
    )
    subprocess.run(
        [str(python), str(root / "scripts" / "smoke.py")], check=True, cwd=base, env=environment
    )
print("Clean wheel installation and core workflow passed")
