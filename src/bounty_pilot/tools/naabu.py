"""naabu wrapper: light port discovery (top ports only) on in-scope hosts."""

from __future__ import annotations

from ..models import OpenPort
from ..scope import Scope, extract_host
from .base import Tool, ToolOutput, iter_json_lines


class Naabu(Tool):
    name = "naabu"
    binary = "naabu"
    go_install = "github.com/projectdiscovery/naabu/v2/cmd/naabu@latest"
    brew = "naabu"

    def build_command(self, path: str, top_ports: int) -> list[str]:
        s = self.settings
        # Top-N ports only; a full 65k-port sweep is deliberately not offered.
        return [path, "-silent", "-json", "-top-ports", str(top_ports),
                "-rate", str(s.rate_limit), "-c", str(s.concurrency)]

    @staticmethod
    def parse(stdout: str) -> list[OpenPort]:
        out: dict[str, OpenPort] = {}
        for obj in iter_json_lines(stdout):
            host = extract_host(obj.get("host") or obj.get("ip"))
            try:
                port = int(obj.get("port"))
            except (TypeError, ValueError):
                continue
            if not host or not 0 < port < 65536:
                continue
            p = OpenPort(host=host, port=port, ip=str(obj.get("ip") or ""))
            out.setdefault(p.key, p)
        return list(out.values())

    def run(self, scope: Scope, hosts: list[str], top_ports: int = 100) -> ToolOutput:
        allowed = scope.filter(hosts)
        if not allowed:
            return ToolOutput()
        path = self.require()
        res = self._exec(self.build_command(path, top_ports), stdin="\n".join(allowed) + "\n")
        items = [p for p in self.parse(res.stdout) if scope.is_allowed(p.host)]
        return self._wrap(items, res)
