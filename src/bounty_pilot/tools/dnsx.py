"""dnsx wrapper: DNS resolution of already-scoped hosts."""

from __future__ import annotations

from ..models import Subdomain
from ..scope import Scope, extract_host
from .base import Tool, ToolOutput, iter_json_lines


class Dnsx(Tool):
    name = "dnsx"
    binary = "dnsx"
    go_install = "github.com/projectdiscovery/dnsx/cmd/dnsx@latest"
    brew = "dnsx"

    def build_command(self, path: str) -> list[str]:
        s = self.settings
        return [path, "-silent", "-json", "-a", "-resp", "-retry", "2",
                "-rl", str(s.rate_limit), "-t", str(s.concurrency)]

    @staticmethod
    def parse(stdout: str) -> list[Subdomain]:
        out: dict[str, Subdomain] = {}
        for obj in iter_json_lines(stdout):
            host = extract_host(obj.get("host"))
            if not host:
                continue
            ips = sorted({str(ip) for ip in (obj.get("a") or []) + (obj.get("aaaa") or [])})
            status = str(obj.get("status_code", "NOERROR")).upper()
            out[host] = Subdomain(host=host, source="dnsx", ips=ips,
                                  resolves=bool(ips) and status == "NOERROR")
        return list(out.values())

    def run(self, scope: Scope, hosts: list[str]) -> ToolOutput:
        allowed = scope.filter(hosts)  # input filter: nothing out of scope gets queried
        if not allowed:
            return ToolOutput()
        path = self.require()
        res = self._exec(self.build_command(path), stdin="\n".join(allowed) + "\n")
        items = [s for s in self.parse(res.stdout) if scope.is_allowed(s.host)]
        return self._wrap(items, res)
