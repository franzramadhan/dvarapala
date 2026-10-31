#!/usr/bin/env python3
"""RFC 0026: one py3-none-<platform> wheel from sdk/python and a built library.

    scripts/wheel.py <platform tag> <library> <out dir>

stdlib only, so the release needs no build tools. The package loads the
library with ctypes, so one wheel serves every Python 3.10+.
"""

import base64
import hashlib
import re
import sys
import tomllib
import zipfile
from pathlib import Path

SDK = Path(__file__).resolve().parent.parent / "sdk" / "python"


def record_line(name: str, data: bytes) -> str:
    digest = base64.urlsafe_b64encode(hashlib.sha256(data).digest()).rstrip(b"=").decode()
    return f"{name},sha256={digest},{len(data)}"


def build(tag: str, library: Path, out: Path) -> Path:
    project = tomllib.loads((SDK / "pyproject.toml").read_text())["project"]
    name, version = project["name"], project["version"]
    readme = (SDK.parent / "README.md").read_text()
    info = f"{name}-{version}.dist-info"
    files = {f"{name}/{p.name}": p.read_bytes() for p in sorted((SDK / "src" / name).glob("*.py"))}
    files[f"{name}/{library.name}"] = library.read_bytes()
    files[f"{info}/METADATA"] = (
        "Metadata-Version: 2.4\n"
        f"Name: {name}\nVersion: {version}\nSummary: {project['description']}\n"
        f"License-Expression: {project['license']}\nRequires-Python: {project['requires-python']}\n"
        "Project-URL: Source, https://github.com/franzramadhan/dvarapala\n"
        f"Description-Content-Type: text/markdown\n\n{readme}"
    ).encode()
    files[f"{info}/WHEEL"] = (
        f"Wheel-Version: 1.0\nGenerator: dvarapala\nRoot-Is-Purelib: false\nTag: py3-none-{tag}\n"
    ).encode()
    record = [record_line(n, d) for n, d in files.items()] + [f"{info}/RECORD,,"]
    files[f"{info}/RECORD"] = ("\n".join(record) + "\n").encode()
    out.mkdir(parents=True, exist_ok=True)
    wheel = out / f"{name}-{version}-py3-none-{tag}.whl"
    with zipfile.ZipFile(wheel, "w", zipfile.ZIP_DEFLATED) as z:
        for n, d in files.items():
            z.writestr(zipfile.ZipInfo(n, (1980, 1, 1, 0, 0, 0)), d, zipfile.ZIP_DEFLATED)
    return wheel


if __name__ == "__main__":
    tag, library, out = sys.argv[1:]
    if not re.fullmatch(r"(manylinux_2_28|macosx_11_0)_(x86_64|aarch64|arm64)", tag):
        sys.exit(f"unexpected platform tag {tag}")
    print(build(tag, Path(library), Path(out)))
