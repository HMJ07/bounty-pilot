"""ffuf wrapper: opt-in content discovery (path enumeration) with a user-supplied wordlist.

This is directory/file *discovery* only. bounty-pilot never uses ffuf for parameter fuzzing,
credential guessing or payload injection.
"""

from __future__ import annotations

import json
import os
import tempfile
from pathlib import Path

from ..models import Endpoint
from ..scope import Scope, extract_host
from .base import Tool, ToolError, ToolOutput


class Ffuf(Tool):
    name = "ffuf"
    binary = "ffuf"
    go_install = "github.com/ffuf/ffuf/v2@latest"
    brew = "ffuf"

    def build_command(self, path: str, base_url: str, wordlist: str, out_file: str) -> list[str]:
        s = self.settings
        return [path, "-u", base_url.rstrip("/") + "/FUZZ", "-w", wordlist, "-of", "json",
                "-o", out_file, "-s", "-mc", "200,204,301,302,307,401,403", "-timeout", "10",
                "-rate", str(s.rate_limit), "-t", str(s.concurrency)]

    @staticmethod
    def parse(text: str) -> list[Endpoint]:
        try:
            data = json.loads(text)
        except (json.JSONDecodeError, TypeError):
            return []
        results = data.get("results") if isinstance(data, dict) else None
        out: dict[str, Endpoint] = {}
        for r in results or []:
            url = r.get("url") if isinstance(r, dict) else None
            host = extract_host(url)
            if url and host:
                ep = Endpoint(url=str(url), host=host, method="GET", source="ffuf")
                out.setdefault(ep.key, ep)
        return list(out.values())

    def run(self, scope: Scope, urls: list[str], wordlist: str) -> ToolOutput:
        wl = Path(wordlist)
        if not wordlist or not wl.is_file():
            raise ToolError(f"ffuf wordlist not found: {wordlist!r} (set ffuf_wordlist in config)")
        path = self.require()
        merged: dict[str, Endpoint] = {}
        out = ToolOutput()
        for url in scope.filter(urls):
            fd, tmp = tempfile.mkstemp(prefix="bp-ffuf-", suffix=".json")
            os.close(fd)
            try:
                res = self._exec(self.build_command(path, url, str(wl), tmp))
                sub = self._wrap([], res)
                out.warnings.extend(sub.warnings)
                out.timed_out = out.timed_out or res.timed_out
                try:
                    text = Path(tmp).read_text(encoding="utf-8")
                except OSError:
                    text = ""
                for ep in self.parse(text):
                    if scope.is_allowed(ep.url):
                        merged.setdefault(ep.key, ep)
            finally:
                try:
                    os.unlink(tmp)
                except OSError:
                    pass
        out.items = list(merged.values())
        return out
