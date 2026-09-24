"""subfinder wrapper: passive subdomain enumeration."""

from __future__ import annotations

from ..models import Subdomain
from ..scope import Scope, extract_host
from .base import RunResult, Tool, ToolOutput, iter_json_lines


class Subfinder(Tool):
    name = "subfinder"
    binary = "subfinder"
    go_install = "github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest"
    brew = "subfinder"

    def build_command(self, path: str, domain: str) -> list[str]:
        s = self.settings
        return [path, "-d", domain, "-silent", "-json", "-rl", str(s.rate_limit),
                "-t", str(s.concurrency), "-timeout", "30"]

    @staticmethod
    def parse(stdout: str) -> list[Subdomain]:
        found: dict[str, Subdomain] = {}
        for obj in iter_json_lines(stdout):
            host = extract_host(obj.get("host"))
            if not host:
                continue
            src = obj.get("source", "")
            if isinstance(src, list):
                src = ",".join(str(x) for x in src)
            found.setdefault(host, Subdomain(host=host, source=str(src)))
        return list(found.values())

    def run(self, scope: Scope, domains: list[str]) -> ToolOutput:
        path = self.require()
        # Seeds come from the scope itself; still re-validated as names (passive lookups only).
        merged: dict[str, Subdomain] = {}
        out = ToolOutput()
        for domain in domains:
            if extract_host(domain) is None:
                continue
            res: RunResult = self._exec(self.build_command(path, domain))
            sub = self._wrap([], res)
            out.warnings.extend(sub.warnings)
            out.timed_out = out.timed_out or res.timed_out
            for s in self.parse(res.stdout):
                if scope.is_allowed(s.host):  # output filter
                    merged.setdefault(s.host, s)
        out.items = list(merged.values())
        return out
