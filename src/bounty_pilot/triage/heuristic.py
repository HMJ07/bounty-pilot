"""Rule-based triage: always available, deterministic, no network.

Priority order (highest first):
    nuclei severity  >  new admin/internal-sounding hosts  >  newly-live services
    >  new open ports / interesting endpoints  >  everything else
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from ..diff import Diff
from ..models import Endpoint, Finding, HttpService

SEVERITY_SCORE = {"critical": 100, "high": 90, "medium": 70, "low": 50, "info": 20}

INTERESTING_HOST = re.compile(
    r"(^|[.-])(admin|administrator|internal|intranet|corp|staging|stage|stg|dev|test|qa|uat|beta|"
    r"preprod|pre-prod|sandbox|demo|jenkins|gitlab|git|ci|vpn|sso|auth|login|oauth|api|backup|old|"
    r"debug|grafana|kibana|jira|confluence|mgmt|manage|console|portal|dashboard|panel|"
    r"monitor|vault|secret)(\d*)([.-]|$)"
)
INTERESTING_TITLE = re.compile(
    r"login|log in|sign in|admin|dashboard|jenkins|grafana|kibana|swagger|phpmyadmin|index of|"
    r"console|gitlab|sonarqube|not for public",
    re.I,
)
INTERESTING_PARAM = re.compile(
    r"[?&](id|uid|user|userid|file|filename|path|dir|url|uri|redirect|next|return|callback|"
    r"token|key|cmd|exec|debug|admin|template|page|include|src|dest|host|domain|q|search)=",
    re.I,
)
INTERESTING_PATH = re.compile(
    r"/(admin|internal|debug|backup|\.git|\.env|swagger|api-docs|graphql|actuator|upload|config|"
    r"console|phpinfo|server-status)(/|\?|$|\.)",
    re.I,
)
SENSITIVE_PORTS = {
    21: "FTP", 22: "SSH", 23: "Telnet", 445: "SMB", 1433: "MSSQL", 2375: "Docker API",
    3306: "MySQL", 3389: "RDP", 5432: "PostgreSQL", 5900: "VNC", 6379: "Redis",
    9200: "Elasticsearch", 11211: "Memcached", 27017: "MongoDB",
}


@dataclass
class TriageItem:
    id: str
    score: int
    category: str  # finding | host | service | change | port | endpoint
    subject: str
    rationale: str
    source: str = "heuristic"  # or "llm"


def _finding(f: Finding) -> tuple[int, str, str]:
    score = SEVERITY_SCORE.get(f.severity, 20)
    return (
        score,
        f"[{f.severity}] {f.name} @ {f.matched_at}",
        f"nuclei template {f.template_id} matched; this is a pattern match only - "
        "verify manually and never assume it is exploitable",
    )


def _service(s: HttpService, new_host: bool) -> tuple[int, str, str]:
    score = 70
    reasons = ["new host" if new_host else "went from no live service to live"]
    if INTERESTING_HOST.search(s.host):
        score += 15
        reasons.append("admin/internal/staging-style hostname")
    if s.title and INTERESTING_TITLE.search(s.title):
        score += 10
        reasons.append(f"title '{s.title[:60]}' suggests a login/admin surface")
    if s.status_code in (401, 403):
        score += 5
        reasons.append(f"returned {s.status_code} (access-controlled)")
    tech = f" [{', '.join(s.technologies[:4])}]" if s.technologies else ""
    # Capped below "critical" findings: a live login page never outranks a critical match.
    return min(score, 95), f"{s.url} (HTTP {s.status_code}){tech}", "; ".join(reasons)


def _endpoint(e: Endpoint) -> tuple[int, str, str]:
    if INTERESTING_PATH.search(e.url):
        return 50, e.url, "new endpoint with a sensitive-looking path"
    if INTERESTING_PARAM.search(e.url):
        return 55, e.url, "new endpoint with an input-handling parameter worth testing"
    if "?" in e.url:
        return 25, e.url, "new endpoint with query parameters"
    return 10, e.url, "new endpoint"


def rank(diff: Diff) -> list[TriageItem]:
    """Rank everything new/changed in ``diff``, best first."""
    raw: list[tuple[int, str, str, str]] = []  # score, category, subject, rationale
    live_hosts = {s.host for s in diff.newly_live}
    new_hosts = {s.host for s in diff.new_subdomains}

    for f in diff.new_findings:
        sc, subj, why = _finding(f)
        raw.append((sc, "finding", subj, why))
    for s in diff.new_subdomains:
        if s.host in live_hosts:
            continue  # reported through its live service below
        score, why = 55, "new subdomain, not (yet) serving HTTP"
        if INTERESTING_HOST.search(s.host):
            score, why = 80, "new subdomain with an admin/internal/staging-style name"
        raw.append((score, "host", s.host, why))
    for s in diff.newly_live:
        sc, subj, why = _service(s, s.host in new_hosts)
        raw.append((sc, "service", subj, why))
    for s in diff.new_services:
        raw.append((45, "service", f"{s.url} (HTTP {s.status_code})", "new service on an existing host"))
    for c in diff.changed_services:
        score, why = 30, f"{c.field} changed"
        if c.field == "technologies":
            score, why = 40, "technology stack changed - possible deploy or new component"
        elif c.field == "status_code" and c.old[:1] in ("4", "5") and c.new[:1] in ("2", "3"):
            score, why = 55, "previously blocked/erroring page is now reachable"
        raw.append((score, "change", f"{c.url}: {c.field} '{c.old}' -> '{c.new}'", why))
    for p in diff.new_ports:
        if p.port in SENSITIVE_PORTS:
            raw.append((65, "port", f"{p.host}:{p.port}",
                        f"new {SENSITIVE_PORTS[p.port]} port exposed"))
        else:
            raw.append((45, "port", f"{p.host}:{p.port}", "new open port"))
    for e in diff.new_endpoints:
        sc, subj, why = _endpoint(e)
        raw.append((sc, "endpoint", subj, why))

    raw.sort(key=lambda r: (-r[0], r[1], r[2]))
    return [
        TriageItem(id=f"i{n:04d}", score=sc, category=cat, subject=subj, rationale=why)
        for n, (sc, cat, subj, why) in enumerate(raw, start=1)
    ]
