"""Pipeline: runs the requested phases in order and produces a new Snapshot.

Robustness rules:

* A phase whose tool is missing (or which fails/crashes) is SKIPPED with a warning; the rest
  of the pipeline continues (degraded-but-useful mode).
* Data for phases that did not run successfully is carried forward from the previous
  snapshot, so a partial run never makes old assets look "new" (or "gone") in the next diff.
* If a tool times out, its partial output is merged with the previous data instead of
  replacing it, so a truncated run does not fabricate "removed" assets.
"""

from __future__ import annotations

import logging
from collections.abc import Callable
from copy import deepcopy

from .config import ALL_PHASES, Config
from .models import Snapshot, Subdomain
from .scope import Scope
from .storage import utcnow
from .tools import Tool, ToolError, ToolNotInstalled
from .tools.base import ToolOutput

log = logging.getLogger("bounty_pilot.pipeline")

# phase -> tools it needs (all listed tools are required unless noted in the phase function)
PHASE_TOOLS = {
    "subdomains": ("subfinder", "dnsx"),
    "http": ("httpx",),
    "crawl": ("katana",),
    "ports": ("naabu",),
    "fuzz": ("ffuf",),
    "nuclei": ("nuclei",),
}


class PhaseError(ValueError):
    pass


def parse_phases(value: str | list[str] | None, default: list[str]) -> list[str]:
    """Validate a phase list and return it in canonical pipeline order."""
    if value is None:
        wanted = list(default)
    elif isinstance(value, str):
        wanted = [p.strip() for p in value.split(",") if p.strip()]
    else:
        wanted = list(value)
    bad = [p for p in wanted if p not in ALL_PHASES]
    if bad:
        raise PhaseError(f"unknown phase(s): {', '.join(bad)}. Valid: {', '.join(ALL_PHASES)}")
    if not wanted:
        raise PhaseError("no phases selected")
    return [p for p in ALL_PHASES if p in wanted]


def _merge(old: list, new: list) -> list:
    merged = {i.key: i for i in old}
    merged.update({i.key: i for i in new})
    return list(merged.values())


class Pipeline:
    def __init__(
        self,
        scope: Scope,
        cfg: Config,
        tools: dict[str, Tool],
        previous: Snapshot | None = None,
        progress: Callable[[str], None] | None = None,
    ):
        self.scope = scope
        self.cfg = cfg
        self.tools = tools
        self.previous = previous
        self._progress = progress or (lambda msg: None)
        self.snap = deepcopy(previous) if previous else Snapshot(target=scope.program)
        self.snap.target = scope.program
        self.snap.run_id = None
        self.snap.warnings = []
        self.completed: list[str] = []

    # ---- helpers ------------------------------------------------------------------
    def _warn(self, msg: str) -> None:
        log.warning(msg)
        self.snap.warnings.append(msg)
        self._progress(f"[warn] {msg}")

    def _tool(self, name: str) -> Tool | None:
        tool = self.tools[name]
        if not tool.available():
            self._warn(f"{name} not installed - {tool.install_hint()}")
            return None
        return tool

    def _absorb(self, out: ToolOutput) -> None:
        for w in out.warnings:
            self._warn(w)

    @staticmethod
    def _apply(current: list, out: ToolOutput, keep_other=lambda i: False) -> list:
        """Combine a tool's output with existing data without fabricating removals.

        * timed out (partial output) -> union with existing data
        * failed with no output       -> keep existing data untouched
        * otherwise                   -> replace (items for which ``keep_other`` is true survive)
        """
        others = [i for i in current if keep_other(i)]
        if out.timed_out:
            return _merge(current, out.items)
        if not out.items and out.warnings:
            return current
        return _merge(others, out.items)

    def _candidate_hosts(self) -> list[str]:
        hosts = [s.host for s in self.snap.subdomains if s.resolves is not False]
        hosts += self.scope.explicit_hosts()
        return self.scope.filter(dict.fromkeys(hosts))

    def _live_urls(self) -> list[str]:
        return self.scope.filter(dict.fromkeys(s.url for s in self.snap.services))

    # ---- phases -------------------------------------------------------------------
    def _phase_subdomains(self) -> bool:
        subfinder = self._tool("subfinder")
        found: list[Subdomain] = [
            Subdomain(host=h, source="scope") for h in self.scope.explicit_hosts()
        ]
        timed_out = False
        if subfinder:
            out = subfinder.run(self.scope, self.scope.seed_domains())  # type: ignore[attr-defined]
            self._absorb(out)
            timed_out = out.timed_out
            found = _merge(found, out.items)
        else:
            self._warn("only hosts listed explicitly in the scope will be used")
        if not found:
            return False
        dnsx = self._tool("dnsx")
        if dnsx:
            out = dnsx.run(self.scope, [s.host for s in found])  # type: ignore[attr-defined]
            self._absorb(out)
            resolved = {s.host: s for s in out.items}
            for s in found:
                r = resolved.get(s.host)
                if r:
                    s.ips, s.resolves = r.ips, r.resolves
                elif not out.timed_out and out.items:
                    s.resolves = False
        else:
            self._warn("subdomains were not DNS-verified")
        self.snap.subdomains = _merge(self.snap.subdomains, found) if timed_out else found
        return True

    def _phase_http(self) -> bool:
        tool = self._tool("httpx")
        hosts = self._candidate_hosts()
        if not tool:
            return False
        if not hosts:
            self._warn("http: no in-scope hosts to probe (run the subdomains phase first?)")
            return False
        out = tool.run(self.scope, hosts)  # type: ignore[attr-defined]
        self._absorb(out)
        self.snap.services = self._apply(self.snap.services, out)
        return True

    def _phase_crawl(self) -> bool:
        tool = self._tool("katana")
        urls = self._live_urls()[: self.cfg.max_crawl_targets]
        if not tool:
            return False
        if not urls:
            self._warn("crawl: no live services known (run the http phase first?)")
            return False
        out = tool.run(self.scope, urls, self.cfg.crawl_depth)  # type: ignore[attr-defined]
        self._absorb(out)
        out.items = out.items[: self.cfg.max_endpoints]
        self.snap.endpoints = self._apply(
            self.snap.endpoints, out, keep_other=lambda e: e.source != "katana"
        )
        return True

    def _phase_ports(self) -> bool:
        tool = self._tool("naabu")
        hosts = self._candidate_hosts()
        if not tool:
            return False
        if not hosts:
            self._warn("ports: no in-scope hosts known")
            return False
        out = tool.run(self.scope, hosts, self.cfg.naabu_top_ports)  # type: ignore[attr-defined]
        self._absorb(out)
        self.snap.ports = self._apply(self.snap.ports, out)
        return True

    def _phase_fuzz(self) -> bool:
        if not self.cfg.ffuf_wordlist:
            self._warn("fuzz: no ffuf_wordlist configured; skipping content discovery")
            return False
        tool = self._tool("ffuf")
        urls = self._live_urls()[: self.cfg.ffuf_max_targets]
        if not tool:
            return False
        if not urls:
            self._warn("fuzz: no live services known")
            return False
        out = tool.run(self.scope, urls, self.cfg.ffuf_wordlist)  # type: ignore[attr-defined]
        self._absorb(out)
        self.snap.endpoints = self._apply(
            self.snap.endpoints, out, keep_other=lambda e: e.source != "ffuf"
        )
        return True

    def _phase_nuclei(self) -> bool:
        tool = self._tool("nuclei")
        urls = self._live_urls()
        if not tool:
            return False
        if not urls:
            self._warn("nuclei: no live services known (run the http phase first?)")
            return False
        out = tool.run(  # type: ignore[attr-defined]
            self.scope, urls, self.cfg.nuclei_severity, self.cfg.nuclei_exclude_tags()
        )
        self._absorb(out)
        self.snap.findings = self._apply(self.snap.findings, out)
        return True

    # ---- driver -------------------------------------------------------------------
    def run(self, phases: list[str]) -> Snapshot:
        self.snap.started_at = utcnow()
        for phase in phases:
            self._progress(f"phase: {phase}")
            try:
                ok = getattr(self, f"_phase_{phase}")()
            except ToolNotInstalled as exc:
                self._warn(str(exc))
                ok = False
            except ToolError as exc:
                self._warn(f"{phase}: {exc}")
                ok = False
            except Exception as exc:  # a crashing phase must never sink the whole run
                log.exception("phase %s crashed", phase)
                self._warn(f"{phase} failed unexpectedly ({type(exc).__name__}: {exc}); skipped")
                ok = False
            if ok:
                self.completed.append(phase)
        self.snap.phases = list(self.completed)
        self.snap.finished_at = utcnow()
        blocked = len(self.scope.blocked)
        if blocked:
            self._warn(f"{blocked} item(s) were blocked by the scope engine (see logs)")
        return self.snap
