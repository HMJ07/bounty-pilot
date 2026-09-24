"""Shared plumbing for external tool wrappers.

Design rules enforced here for every wrapper:

* Commands are argument *lists* executed with ``shell=False``; input data goes via stdin,
  never through string concatenation into a shell line.
* A missing binary raises :class:`ToolNotInstalled` (with install instructions), which the
  pipeline turns into "skip this phase, warn, continue".
* Every call has a hard wall-clock timeout; a hung tool is killed and any partial output is
  still parsed.
* Wrappers filter their inputs *and* outputs through the scope engine.
"""

from __future__ import annotations

import json
import shutil
import subprocess
from collections.abc import Callable, Iterator, Sequence
from dataclasses import dataclass, field
from typing import Any

from ..config import ToolSettings


class ToolError(Exception):
    """Base class for wrapper errors."""


class ToolNotInstalled(ToolError):
    def __init__(self, tool: str, hint: str):
        super().__init__(f"{tool} is not installed. {hint}")
        self.tool = tool
        self.hint = hint


@dataclass
class RunResult:
    returncode: int
    stdout: str = ""
    stderr: str = ""
    timed_out: bool = False


@dataclass
class ToolOutput:
    items: list[Any] = field(default_factory=list)
    timed_out: bool = False
    warnings: list[str] = field(default_factory=list)


Runner = Callable[[Sequence[str], float, "str | None"], RunResult]
Which = Callable[[str], "str | None"]


def _text(value: object) -> str:
    if value is None:
        return ""
    if isinstance(value, bytes):
        return value.decode("utf-8", errors="replace")
    return str(value)


def default_runner(args: Sequence[str], timeout: float, stdin: str | None = None) -> RunResult:
    """Run an argument list without a shell. The only place subprocess is used for tools."""
    try:
        proc = subprocess.run(
            list(args),
            input=stdin,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=timeout,
            shell=False,
            check=False,
        )
    except subprocess.TimeoutExpired as exc:
        return RunResult(-1, _text(exc.stdout), _text(exc.stderr), timed_out=True)
    except FileNotFoundError as exc:
        raise ToolNotInstalled(str(args[0]), "Binary not found on PATH.") from exc
    return RunResult(proc.returncode, proc.stdout or "", proc.stderr or "")


def iter_json_lines(text: str) -> Iterator[dict[str, Any]]:
    """Yield JSON objects from JSON-lines output, skipping banners / garbage lines."""
    for line in text.splitlines():
        line = line.strip()
        if not line.startswith("{"):
            continue
        try:
            obj = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(obj, dict):
            yield obj


class Tool:
    name: str = ""
    binary: str = ""
    go_install: str = ""
    brew: str = ""
    # If set, `<binary> -version` output must contain one of these (case-insensitive).
    # Guards against same-named binaries, e.g. the Python `httpx` CLI vs ProjectDiscovery's.
    identity_markers: tuple[str, ...] = ()

    def __init__(
        self,
        settings: ToolSettings,
        runner: Runner | None = None,
        which: Which | None = None,
    ):
        self.settings = settings
        self._runner: Runner = runner or default_runner
        self._which: Which = which or shutil.which

    # ---- availability -------------------------------------------------------------
    def path(self) -> str | None:
        return self._which(self.binary)

    def available(self) -> bool:
        path = self.path()
        if not path:
            return False
        if not self.identity_markers:
            return True
        try:
            res = self._runner([path, "-version"], 20, None)
        except ToolError:
            return False
        blob = (res.stdout + res.stderr).lower()
        return any(m in blob for m in self.identity_markers)

    def install_hint(self) -> str:
        parts = []
        if self.go_install:
            parts.append(f"go install -v {self.go_install}")
        if self.brew:
            parts.append(f"brew install {self.brew}")
        hint = "Install with: " + "  |  ".join(parts) if parts else ""
        return (hint + "  (run `bountypilot doctor` for details)").strip()

    def require(self) -> str:
        if not self.available():
            raise ToolNotInstalled(self.name, self.install_hint())
        path = self.path()
        assert path is not None
        return path

    # ---- execution ----------------------------------------------------------------
    def _exec(self, args: Sequence[str], stdin: str | None = None) -> RunResult:
        return self._runner(args, float(self.settings.timeout), stdin)

    def _wrap(self, items: list[Any], res: RunResult) -> ToolOutput:
        out = ToolOutput(items=items, timed_out=res.timed_out)
        if res.timed_out:
            out.warnings.append(
                f"{self.name} exceeded its {self.settings.timeout}s timeout and was stopped; "
                "results may be partial"
            )
        elif res.returncode != 0 and not items:
            tail = (res.stderr or "").strip().splitlines()[-1:] or [""]
            out.warnings.append(f"{self.name} exited with code {res.returncode}: {tail[0][:200]}")
        return out
