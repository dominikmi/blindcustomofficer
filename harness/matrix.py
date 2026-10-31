# /// script
# requires-python = ">=3.12"
# dependencies = ["polars>=1.0", "pydantic>=2.0", "ruamel.yaml>=0.18"]
# ///
"""Aggregate per-test scan results vs ground truth into the detection matrix.

For each test x scanner, classifies the CVE-2026-111497 outcome as:
  detected              - the CVE (or a known alias/derivative) appears in results
  enumerated-unmatched  - component in the SBOM but no CVE attached
  not-enumerated        - component absent from the SBOM entirely
  scanner-na            - scanner produced no usable output

Run:  uv run matrix.py            (from harness/)
"""
from __future__ import annotations

import json
import re
from pathlib import Path

import polars as pl
from pydantic import BaseModel
from ruamel.yaml import YAML

ROOT = Path(__file__).resolve().parent.parent
TESTS = ROOT / "tests"
REPORT = ROOT / "report"

# (column, candidate files in priority order)
SCANNERS: tuple[tuple[str, tuple[str, ...]], ...] = (
    ("grype.image", ("grype.image.json",)),
    ("grype.sbom", ("grype.sbom.json",)),
    ("trivy", ("trivy.json",)),
    ("snyk", ("snyk.json",)),
    ("snyk.sbom", ("snyk.sbom.json",)),
    ("snyk.unmanaged", ("snyk.unmanaged.json",)),
    ("scout", ("scout.sarif.json", "scout.txt")),
)

# Any of these strings in a scanner's JSON counts as "the CVE was surfaced".
MATCH_TERMS = (
    "CVE-2026-111497",
    "GHSA-9v8h-qqgm-4m35",
    "PYSEC-2026-4322",
    "PYSEC-2026-4323",
    "SNYK-JAVA-COMAAYUSHATHARVABROTLI4J-21762877",
    "111497",
)

def enumerated_in_sbom(sbom_path: Path, name_re: re.Pattern[str], ptype: str) -> bool:
    """Was the PLANTED component enumerated? Matches artifact name/type from
    the per-test match spec — not incidental base-image packages."""
    if not sbom_path.exists() or sbom_path.stat().st_size == 0:
        return False
    try:
        data = json.loads(sbom_path.read_text())
    except json.JSONDecodeError:
        return False
    for art in data.get("artifacts", []):
        if ptype != "any" and art.get("type") != ptype:
            continue
        if name_re.search(str(art.get("name", ""))):
            return True
    return False


class TestResult(BaseModel):
    test: str
    role: str
    vector: str
    enumerated: bool
    scanner_outcome: dict[str, str]


def scanner_outcome(result_dir: Path, enumerated: bool) -> dict[str, str]:
    out: dict[str, str] = {}
    for name, candidates in SCANNERS:
        text = ""
        for cand in candidates:
            f = result_dir / cand
            if f.exists() and f.stat().st_size > 0:
                text = f.read_text(errors="replace")
                break
        if not text or text.startswith("Display CVEs"):
            out[name] = "scanner-na"
        elif any(term in text for term in MATCH_TERMS):
            out[name] = "detected"
        else:
            out[name] = "enumerated-unmatched" if enumerated else "not-enumerated"
    return out


def main() -> None:
    yaml = YAML(typ="safe")
    truth = yaml.load((ROOT / "ground_truth.yaml").read_text())

    rows: list[dict[str, str]] = []
    for test_dir in sorted(TESTS.iterdir()):
        if not test_dir.is_dir():
            continue
        meta = truth["tests"].get(test_dir.name, {})
        spec = meta.get("match", {})
        name_re = re.compile(spec.get("name", r"brotli"), re.I)
        ptype = spec.get("type", "any")
        sbom = test_dir / "results" / "syft.sbom.json"
        enum = enumerated_in_sbom(sbom, name_re, ptype)
        outcomes = scanner_outcome(test_dir / "results", enum)
        rows.append(
            {
                "test": test_dir.name,
                "role": meta.get("role", "?"),
                "vector": meta.get("vector", "?"),
                "enumerated": str(enum),
                **outcomes,
            }
        )

    df = pl.DataFrame(rows)
    REPORT.mkdir(exist_ok=True)
    df.write_csv(REPORT / "matrix.csv")
    print(df)
    print(f"\nwrote {REPORT / 'matrix.csv'}")


if __name__ == "__main__":
    main()
