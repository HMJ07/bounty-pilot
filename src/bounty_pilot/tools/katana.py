"""katana wrapper: crawl live services to collect endpoints."""

from __future__ import annotations

from ..models import Endpoint
from ..scope import Scope, extract_host
from .base import Tool, ToolOutput, iter_json_lines


class Katana(Tool):
    name = "katana"
    binary = "katana"
    go_install = "github.com/projectdiscovery/katana/cmd/katana@latest"
    brew = "katana"

    def build_command(self, path: str, depth: int) -> list[str]:
        s = self.settings
        # `-fs fqdn` keeps the crawler on the exact host it was given. The default (rdn) would
        # follow links to sibling subdomains that may be out of scope.
        return [path, "-silent", "-jsonl", "-nc", "-d", str(depth), "-fs", "fqdn",
                "-timeout", "10", "-rl", str(s.rate_limit), "-c", str(s.concurrency)]

    @staticmethod
    def parse(stdout: str) -> list[Endpoint]:
        out: dict[str, Endpoint] = {}

        def add(url: object, method: object = "GET") -> None:
            host = extract_host(url)
            if not host or not isinstance(url, str):
                return
            ep = Endpoint(url=url, host=host, method=str(method or "GET").upper(), source="katana")
            out.setdefault(ep.key, ep)

        json_seen = False
        for obj in iter_json_lines(stdout):
            json_seen = True
            req = obj.get("request") or {}
            add(req.get("endpoint") or obj.get("endpoint") or obj.get("url"), req.get("method"))
        if not json_seen:  # older katana versions print bare URLs
            for line in stdout.splitlines():
                line = line.strip()
                if line.startswith(("http://", "https://")):
                    add(line)
        return list(out.values())

    def run(self, scope: Scope, urls: list[str], depth: int = 2) -> ToolOutput:
        allowed = scope.filter(urls)
        if not allowed:
            return ToolOutput()
        path = self.require()
        res = self._exec(self.build_command(path, depth), stdin="\n".join(allowed) + "\n")
        items = [e for e in self.parse(res.stdout) if scope.is_allowed(e.url)]
        return self._wrap(items, res)
