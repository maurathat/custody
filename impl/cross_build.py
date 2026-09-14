"""Rebuild the generated files under other Python interpreters and record the byte comparison.

    python impl/cross_build.py PYTHON [PYTHON ...]

Each PYTHON must have impl/requirements.txt installed. For each one, the repository is copied
to a temporary directory, the generated files are deleted from the copy, and
build_vectors.generate() rewrites them under that interpreter. Each rewritten file is then
compared byte for byte with this checkout's. vectors/CROSS_BUILD records the results and the
SHA-256 of the vectors.json they were compared against, and impl/verify.py fails once that is
no longer the current vectors.json. The record lists only the interpreters it was given, so it
reflects the machine it ran on, like vectors/BUILD_ENV. Run impl/build_vectors.py afterwards so
SHA256SUMS and README.md pick it up.
"""
from __future__ import annotations

import hashlib
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
GENERATED = ("vectors/vectors.json", "example/chain.json", "vectors/BUILD_ENV")
IGNORED = shutil.ignore_patterns(".git", ".venv", "__pycache__", ".DS_Store")


def rebuild(python: str) -> str:
    with tempfile.TemporaryDirectory() as scratch:
        copy = Path(scratch) / "repo"
        shutil.copytree(ROOT, copy, ignore=IGNORED)
        for name in GENERATED:
            (copy / name).unlink(missing_ok=True)
        subprocess.run([python, "-c", "import build_vectors; build_vectors.generate()"], cwd=copy / "impl", check=True)
        env = dict(line.split(" ", 1) for line in (copy / "vectors" / "BUILD_ENV").read_text().splitlines()
                   if line and not line.startswith("#"))
        fields = [f"python {env['python']}", f"unicode {env['unicode']}", f"rfc8785 {env['rfc8785']}"]
        for name in GENERATED:
            same = (copy / name).read_bytes() == (ROOT / name).read_bytes()
            fields.append(f"{Path(name).name} {'identical' if same else 'differs'}")
        return " ".join(fields)


def main(pythons: list) -> int:
    if not pythons:
        sys.stderr.write(__doc__)
        return 2
    rows = sorted(rebuild(python) for python in pythons)
    compared = hashlib.sha256((ROOT / "vectors" / "vectors.json").read_bytes()).hexdigest()
    (ROOT / "vectors" / "CROSS_BUILD").write_text(
        "# Written by impl/cross_build.py. Each line is one interpreter's rebuild, compared byte for\n"
        "# byte with the files in this checkout. Recorded where it was run, like BUILD_ENV.\n"
        f"compared-against {compared}\n" + "".join(f"{row}\n" for row in rows))
    sys.stdout.write("".join(f"{row}\n" for row in rows))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
