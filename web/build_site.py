"""Assemble the static demo site: page, sample policy and the Python package.

Usage: python web/build_site.py [output_dir]   (default: _site)
Preview: python -m http.server -d _site 8000
"""

from __future__ import annotations

import json
import shutil
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
WEB = ROOT / "web"
PACKAGE = ROOT / "src" / "firewall_validation_engine"


def build(out: Path) -> Path:
    if out.exists():
        shutil.rmtree(out)
    (out / "py").mkdir(parents=True)
    for name in ("index.html", "app.js", "style.css"):
        shutil.copy(WEB / name, out / name)
    (out / "samples").mkdir()
    shutil.copy(ROOT / "samples" / "policy.json", out / "samples" / "policy.json")

    files = ["bridge.py"]
    shutil.copy(WEB / "bridge.py", out / "py" / "bridge.py")
    for source in sorted(PACKAGE.glob("*.py")):
        rel = f"{PACKAGE.name}/{source.name}"
        (out / "py" / PACKAGE.name).mkdir(exist_ok=True)
        shutil.copy(source, out / "py" / rel)
        files.append(rel)
    (out / "py" / "manifest.json").write_text(json.dumps(files, indent=1), encoding="utf-8")
    (out / ".nojekyll").write_text("", encoding="utf-8")
    return out


if __name__ == "__main__":
    target = build(Path(sys.argv[1]) if len(sys.argv) > 1 else ROOT / "_site")
    print(f"site written to {target}")
