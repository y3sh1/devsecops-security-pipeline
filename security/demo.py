"""Reproduce a blocked candidate and its fix using fresh scanner runs."""

import argparse
import json
from pathlib import Path
import shutil
import sys
import tempfile

from check import scan


ROOT = Path(__file__).resolve().parents[1]


def run(output):
    output.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory() as work:
        target = Path(work) / "candidate"
        shutil.copytree(ROOT / "service", target, ignore=shutil.ignore_patterns("__pycache__"))
        safe_dockerfile = (target / "Dockerfile").read_text(encoding="utf-8")
        root_dockerfile = safe_dockerfile.replace("USER 10001:10001", "USER root")
        if safe_dockerfile == root_dockerfile:
            raise ValueError("could not stage the Dockerfile regression")
        (target / "Dockerfile").write_text(root_dockerfile, encoding="utf-8")
        changes = ROOT / "demo" / "changes"
        shutil.copyfile(changes / "raw_headers.fixture", target / "audit_candidate.py")
        shutil.copyfile(changes / "dependency.fixture", target / "requirements.txt")

        before = scan(target)
        (target / "audit_candidate.py").unlink()
        for name in ("requirements.txt", "Dockerfile"):
            shutil.copyfile(ROOT / "service" / name, target / name)
        after = scan(target)
    for name, report in (("before", before), ("after", after)):
        (output / f"{name}.json").write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
        print(f"{name}: {report['decision']} ({len(report['findings'])} findings)")
    found = {row["kind"] for row in before["findings"] if row["blocking"]}
    expected = {"code", "configuration", "dependency"}
    if not expected.issubset(found) or after["decision"] != "PASS":
        print(f"Unexpected outcome. Inspect {output}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, default=Path("reports/demo"))
    raise SystemExit(run(parser.parse_args().output))
