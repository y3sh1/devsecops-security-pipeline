"""Scan a checkout, apply the merge policy and write a redacted JSON report."""

import argparse
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile


RULES = Path(__file__).with_name("rules.yml").resolve()
HIGH = {"HIGH", "CRITICAL"}
TOOL_ENV = {"semgrep": "SEMGREP_BIN", "trivy": "TRIVY_BIN"}


def command(tool, *args, cwd):
    binary = os.environ.get(TOOL_ENV[tool], tool)
    subprocess.run([binary, *map(str, args)], cwd=cwd, check=True)


def normalize(semgrep, trivy):
    if not isinstance(semgrep.get("results"), list) or semgrep.get("errors") != []:
        raise ValueError("Semgrep returned an incomplete report")
    if trivy.get("SchemaVersion") != 2 or not isinstance(trivy.get("Results", []), list):
        raise ValueError("unsupported Trivy report")
    rows = []
    for item in semgrep["results"]:
        severity = item["extra"]["severity"]
        rows.append({"kind": "code", "id": item["check_id"].split(".")[-1],
                     "path": item["path"], "line": item["start"]["line"],
                     "severity": severity, "blocking": severity == "ERROR"})
    for result in trivy.get("Results", []):
        path = result["Target"]
        for item in result.get("Vulnerabilities", []):
            fix = item.get("FixedVersion", "")
            severity = item["Severity"]
            rows.append({"kind": "dependency", "id": item["VulnerabilityID"],
                         "path": path, "package": item["PkgName"],
                         "installed": item["InstalledVersion"], "fix": fix,
                         "severity": severity, "blocking": severity in HIGH})
        for item in result.get("Misconfigurations", []):
            if item.get("Status") != "FAIL":
                continue
            severity = item["Severity"]
            rows.append({"kind": "configuration", "id": item.get("AVDID") or item["ID"],
                         "path": path, "severity": severity, "blocking": severity in HIGH})
        for item in result.get("Secrets", []):
            rows.append({"kind": "secret", "id": item["RuleID"], "path": path,
                         "line": item["StartLine"], "severity": item["Severity"], "blocking": True})
    rows.sort(key=lambda row: (row["kind"], row["path"], row["id"], row.get("line", 0)))
    return {"decision": "BLOCK" if any(row["blocking"] for row in rows) else "PASS",
            "findings": rows}


def scan(target):
    with tempfile.TemporaryDirectory() as raw:
        sem_path = Path(raw) / "semgrep.json"
        tri_path = Path(raw) / "trivy.json"
        command("semgrep", "scan", "--config", RULES, "--strict", "--metrics=off",
                "--disable-version-check", "--disable-nosem", "--no-git-ignore",
                "--exclude=.git", "--exclude=.venv", "--exclude=__pycache__",
                "--json", "--output", sem_path, ".", cwd=target)
        command("trivy", "fs", "--scanners", "vuln,misconfig,secret", "--no-progress",
                "--skip-dirs", ".git", "--skip-dirs", ".venv", "--skip-dirs", "__pycache__",
                "--format", "json", "--output", tri_path, ".", cwd=target)
        return normalize(json.loads(sem_path.read_bytes()), json.loads(tri_path.read_bytes()))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--target", type=Path, default=Path.cwd())
    parser.add_argument("--report", type=Path, default=Path("reports/security.json"))
    args = parser.parse_args()
    args.report.unlink(missing_ok=True)
    try:
        report = scan(args.target.resolve(strict=True))
        args.report.parent.mkdir(parents=True, exist_ok=True)
        args.report.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    except (OSError, ValueError, KeyError, subprocess.CalledProcessError) as error:
        print(f"INCOMPLETE: {error}", file=sys.stderr)
        return 2
    blockers = sum(row["blocking"] for row in report["findings"])
    print(f"{report['decision']}: {blockers} blocking, {len(report['findings'])} total")
    return int(report["decision"] == "BLOCK")


if __name__ == "__main__":
    raise SystemExit(main())
