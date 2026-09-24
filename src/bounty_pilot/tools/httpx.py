"""httpx (ProjectDiscovery) wrapper: probe hosts for live HTTP(S) services."""

from __future__ import annotations

from ..models import HttpService
from ..scope import Scope, extract_host
from .base import Tool, ToolOutput, iter_json_lines


def _int(value: object) -> int | None:
    try:
        return int(value)  # type: ignore[call-overload]
    except (TypeError, ValueError):
        return None


class Httpx(Tool):
    name = "httpx"
    binary = "httpx"
    go_install = "github.com/projectdiscovery/httpx/cmd/httpx@latest"
    brew = "httpx"
    # The Python package `httpx` also installs a CLI called `httpx`; make sure we got PD's.
    identity_markers = ("projectdiscovery", "current version")

    def build_command(self, path: str) -> list[str]:
        s = self.settings
        # Redirects are NOT followed (no -fr): a redirect could lead outside the scope.
        return [path, "-silent", "-json", "-nc", "-sc", "-title", "-server", "-td", "-cl",
                "-timeout", "10", "-rl", str(s.rate_limit), "-t", str(s.concurrency)]

    @staticmethod
    def parse(stdout: str) -> list[HttpService]:
        out: dict[str, HttpService] = {}
        for obj in iter_json_lines(stdout):
            url = obj.get("url")
            host = extract_host(url)
            if not url or not host:
                continue
            tech = obj.get("tech") or obj.get("technologies") or []
            ip = obj.get("host_ip") or ""
            if not ip:
                a = obj.get("a")
                ip = a[0] if isinstance(a, list) and a else ""
            out[url] = HttpService(
                url=str(url),
                host=host,
                status_code=_int(obj.get("status_code")),
                title=str(obj.get("title") or "").strip(),
                server=str(obj.get("webserver") or obj.get("server") or ""),
                technologies=sorted({str(t) for t in tech}),
                content_length=_int(obj.get("content_length")),
                ip=str(ip),
            )
        return list(out.values())

    def run(self, scope: Scope, hosts: list[str]) -> ToolOutput:
        allowed = scope.filter(hosts)
        if not allowed:
            return ToolOutput()
        path = self.require()
        res = self._exec(self.build_command(path), stdin="\n".join(allowed) + "\n")
        items = [s for s in self.parse(res.stdout) if scope.is_allowed(s.url)]
        return self._wrap(items, res)
