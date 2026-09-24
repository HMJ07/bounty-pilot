"""Thin, scope-enforcing wrappers around external recon tools."""

from __future__ import annotations

from ..config import Config
from .base import Runner, Tool, ToolError, ToolNotInstalled, Which
from .dnsx import Dnsx
from .ffuf import Ffuf
from .httpx import Httpx
from .katana import Katana
from .naabu import Naabu
from .nuclei import Nuclei
from .subfinder import Subfinder

TOOL_CLASSES: dict[str, type[Tool]] = {
    "subfinder": Subfinder,
    "dnsx": Dnsx,
    "httpx": Httpx,
    "katana": Katana,
    "naabu": Naabu,
    "ffuf": Ffuf,
    "nuclei": Nuclei,
}


def build_tools(cfg: Config, runner: Runner | None = None, which: Which | None = None) -> dict[str, Tool]:
    return {n: cls(cfg.tools[n], runner=runner, which=which) for n, cls in TOOL_CLASSES.items()}


__all__ = ["TOOL_CLASSES", "Tool", "ToolError", "ToolNotInstalled", "build_tools"]
