"""nuclei wrapper: template-based detection. This is the ceiling of automatic checking.

bounty-pilot never adds exploitation or confirmation logic on top of nuclei. Templates tagged
dos / intrusive / fuzz / bruteforce / default-login are always excluded, interactsh
(out-of-band callbacks to third-party servers) is disabled, and info-level noise is off by
default.
"""

from __future__ import annotations

from ..models import Finding, normalize_severity
from ..scope import Scope, extract_host
from .base import Tool, ToolOutput, iter_json_lines


class Nuclei(Tool):
    name = "nuclei"
    binary = "nuclei"
    go_install = "github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest"
    brew = "nuclei"

    def build_command(self, path: str, severities: list[str], exclude_tags: list[str]) -> list[str]:
        s = self.settings
        return [path, "-silent", "-jsonl", "-nc", "-duc", "-ni",
                "-severity", ",".join(severities), "-etags", ",".join(exclude_tags),
                "-timeout", "10", "-rl", str(s.rate_limit), "-c", str(s.concurrency)]

    @staticmethod
    def parse(stdout: str) -> list[Finding]:
        out: dict[str, Finding] = {}
        for obj in iter_json_lines(stdout):
            tid = obj.get("template-id") or obj.get("templateID")
            if not tid:
                continue
            info = obj.get("info") or {}
            matched = str(obj.get("matched-at") or obj.get("matched") or obj.get("host") or "")
            host = extract_host(matched) or extract_host(obj.get("host"))
            if not host:
                continue
            tags = info.get("tags") or []
            if isinstance(tags, str):
                tags = [t.strip() for t in tags.split(",") if t.strip()]
            f = Finding(
                template_id=str(tid),
                name=str(info.get("name") or tid),
                severity=normalize_severity(info.get("severity")),
                host=host,
                matched_at=matched or host,
                description=str(info.get("description") or "").strip(),
                tags=[str(t) for t in tags],
            )
            out.setdefault(f.key, f)
        return list(out.values())

    def run(
        self,
        scope: Scope,
        targets: list[str],
        severities: list[str],
        exclude_tags: list[str],
    ) -> ToolOutput:
        allowed = scope.filter(targets)
        if not allowed:
            return ToolOutput()
        path = self.require()
        cmd = self.build_command(path, severities, exclude_tags)
        res = self._exec(cmd, stdin="\n".join(allowed) + "\n")
        items = [f for f in self.parse(res.stdout) if scope.is_allowed(f.matched_at)]
        return self._wrap(items, res)
