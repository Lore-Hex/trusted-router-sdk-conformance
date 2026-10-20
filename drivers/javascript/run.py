#!/usr/bin/env python3
"""Install the locked transport outside packaged assets, then run the JS driver."""

from __future__ import annotations

import hashlib
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path


def main() -> int:
    root = Path(__file__).resolve().parent
    lock = root / "package-lock.json"
    digest = hashlib.sha256(lock.read_bytes()).hexdigest()[:16]
    cache = Path(tempfile.gettempdir()) / "trusted-router-conformance-javascript" / digest
    module = cache / "node_modules" / "undici" / "index.js"
    if not module.is_file():
        cache.mkdir(parents=True, exist_ok=True)
        for name in ("package.json", "package-lock.json"):
            shutil.copyfile(root / name, cache / name)
        subprocess.run(
            ["npm", "ci", "--ignore-scripts", "--no-audit", "--no-fund"],
            cwd=cache,
            check=True,
        )
    env = {**os.environ, "TR_CONFORMANCE_UNDICI_MODULE": str(module)}
    return subprocess.run(["node", str(root / "driver.mjs")], env=env, check=False).returncode


if __name__ == "__main__":
    sys.exit(main())
