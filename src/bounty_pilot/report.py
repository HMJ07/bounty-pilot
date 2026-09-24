"""Report generator for findings a human has MANUALLY confirmed.

bounty-pilot never drafts a report from a raw tool detection: a nuclei match is a lead, not a
vulnerability. This module only formats what the researcher types in (or supplies in a
YAML/JSON file) into a HackerOne- or Bugcrowd-style Markdown submission.
"""

from __future__ import annotations

import json
import re
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

FORMATS = ("hackerone", "bugcrowd", "generic")
SEVERITIES = ("none", "low", "medium", "high", "critical")
_VECTOR = re.compile(r"^CVSS:3\.[01]/(AV|AC|PR|UI|S|C|I|A)[:]")


class ReportError(ValueError):
    pass


def severity_from_cvss(score: float) -> str:
    if score <= 0:
        return "none"
    if score < 4.0:
        return "low"
    if score < 7.0:
        return "medium"
    if score < 9.0:
        return "high"
    return "critical"


@dataclass
class ReportData:
    title: str
    asset: str
    vuln_class: str
    steps: list[str]
    impact: str
    summary: str = ""
    severity: str = ""
    cvss_score: float | None = None
    cvss_vector: str = ""
    remediation: str = ""
    references: list[str] = field(default_factory=list)
    program: str = ""

    REQUIRED = ("title", "asset", "vuln_class", "steps", "impact")

    @classmethod
    def from_mapping(cls, data: Any) -> ReportData:
        if not isinstance(data, dict):
            raise ReportError("report input must be a mapping")
        missing = [k for k in cls.REQUIRED if not data.get(k)]
        if missing:
            raise ReportError("missing required field(s): " + ", ".join(missing))
        steps = data["steps"]
        if isinstance(steps, str):
            steps = [ln.strip() for ln in steps.splitlines() if ln.strip()]
        if not isinstance(steps, list) or not steps:
            raise ReportError("'steps' must be a non-empty list")
        score = data.get("cvss_score")
        if score is not None:
            try:
                score = float(score)
            except (TypeError, ValueError) as exc:
                raise ReportError("cvss_score must be a number") from exc
            if not 0.0 <= score <= 10.0:
                raise ReportError("cvss_score must be between 0.0 and 10.0")
        vector = str(data.get("cvss_vector") or "").strip()
        if vector and not _VECTOR.match(vector):
            raise ReportError("cvss_vector must be a CVSS v3.x vector string (CVSS:3.1/AV:N/...)")
        severity = str(data.get("severity") or "").strip().lower()
        if severity and severity not in SEVERITIES:
            raise ReportError(f"severity must be one of: {', '.join(SEVERITIES)}")
        if not severity and score is not None:
            severity = severity_from_cvss(score)
        refs = data.get("references") or []
        if isinstance(refs, str):
            refs = [refs]
        return cls(
            title=str(data["title"]).strip(),
            asset=str(data["asset"]).strip(),
            vuln_class=str(data["vuln_class"]).strip(),
            steps=[str(s).strip() for s in steps],
            impact=str(data["impact"]).strip(),
            summary=str(data.get("summary") or "").strip(),
            severity=severity,
            cvss_score=score,
            cvss_vector=vector,
            remediation=str(data.get("remediation") or "").strip(),
            references=[str(r) for r in refs],
            program=str(data.get("program") or "").strip(),
        )


def load_report_file(path: str | Path) -> ReportData:
    p = Path(path)
    text = p.read_text(encoding="utf-8")
    try:
        data = json.loads(text) if p.suffix.lower() == ".json" else yaml.safe_load(text)
    except (json.JSONDecodeError, yaml.YAMLError) as exc:
        raise ReportError(f"could not parse {p.name}: {exc}") from exc
    return ReportData.from_mapping(data)


def _severity_line(d: ReportData) -> str:
    parts = []
    if d.severity:
        parts.append(d.severity.capitalize())
    if d.cvss_score is not None:
        parts.append(f"CVSS {d.cvss_score:.1f}")
    return " - ".join(parts) if parts else "To be determined by the program"


def _numbered(steps: list[str]) -> str:
    return "\n".join(f"{i}. {s}" for i, s in enumerate(steps, start=1))


def _summary(d: ReportData) -> str:
    return d.summary or f"{d.vuln_class} in `{d.asset}`."


def _refs(d: ReportData) -> str:
    return "\n".join(f"- {r}" for r in d.references)


def render(d: ReportData, fmt: str = "hackerone") -> str:
    """Render Markdown in the requested house style."""
    if fmt not in FORMATS:
        raise ReportError(f"unknown format {fmt!r}; choose from {', '.join(FORMATS)}")
    vector = f"  \n**CVSS vector:** `{d.cvss_vector}`" if d.cvss_vector else ""
    remediation = d.remediation or "_No remediation suggested by the reporter._"
    if fmt == "bugcrowd":
        out = [
            f"# {d.title}",
            "",
            f"**Target:** {d.asset}  ",
            f"**Vulnerability type:** {d.vuln_class}  ",
            f"**Suggested priority / severity:** {_severity_line(d)}{vector}",
            "",
            "## Description",
            _summary(d),
            "",
            "## Steps to reproduce",
            _numbered(d.steps),
            "",
            "## Impact",
            d.impact,
            "",
            "## Recommended fix",
            remediation,
        ]
    else:
        out = [
            f"# {d.title}",
            "",
            "## Summary",
            _summary(d),
            "",
            f"**Asset:** {d.asset}  ",
            f"**Weakness:** {d.vuln_class}  ",
            f"**Severity:** {_severity_line(d)}{vector}",
            "",
            "## Steps to Reproduce",
            _numbered(d.steps),
            "",
            "## Impact",
            d.impact,
            "",
            "## Remediation",
            remediation,
        ]
    if d.references:
        out += ["", "## References" if fmt != "bugcrowd" else "## Supporting material", _refs(d)]
    out += ["", "<!-- Formatted with bounty-pilot. Findings must be manually verified before submission. -->", ""]
    return "\n".join(out)


def collect_interactive(
    ask: Callable[[str], str] = input,
    say: Callable[[str], None] = print,
) -> ReportData:
    """Walk the researcher through the report fields. ``ask``/``say`` are injectable."""

    def required(prompt: str) -> str:
        while True:
            v = ask(f"{prompt}: ").strip()
            if v:
                return v
            say("  (required)")

    say("Only report issues you have manually verified on an in-scope asset.")
    title = required("Title")
    asset = required("Affected asset / URL")
    vuln_class = required("Vulnerability class (e.g. IDOR, Stored XSS)")
    summary = ask("One-paragraph summary (optional): ").strip()
    say("Steps to reproduce - one per line, empty line to finish:")
    steps: list[str] = []
    while True:
        line = ask(f"  {len(steps) + 1}. ").strip()
        if not line:
            if steps:
                break
            say("  (at least one step required)")
            continue
        steps.append(line)
    impact = required("Impact")
    cvss = ask("CVSS 3.x base score 0-10 (optional): ").strip()
    vector = ask("CVSS vector (optional): ").strip()
    severity = ask(f"Severity [{'/'.join(SEVERITIES)}] (optional, derived from CVSS if empty): ").strip()
    remediation = ask("Suggested remediation (optional): ").strip()
    return ReportData.from_mapping(
        {
            "title": title, "asset": asset, "vuln_class": vuln_class, "summary": summary,
            "steps": steps, "impact": impact, "cvss_score": cvss or None,
            "cvss_vector": vector, "severity": severity, "remediation": remediation,
        }
    )
