"""Configuration: conservative, polite-by-default limits plus optional LLM / notification setup."""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

ALL_PHASES = ("subdomains", "http", "crawl", "ports", "fuzz", "nuclei")
# ports (active port scan) and fuzz (content discovery) are noisier: opt-in only.
DEFAULT_PHASES = ("subdomains", "http", "crawl", "nuclei")

# Nuclei tags that are excluded ALWAYS. Users can add more but can never remove these.
# They cover denial-of-service, intrusive checks, fuzzing and credential guessing, i.e.
# everything beyond passive/pattern-matching detection.
FORBIDDEN_NUCLEI_TAGS = ("dos", "intrusive", "fuzz", "bruteforce", "brute-force", "default-login")


class ConfigError(ValueError):
    pass


def home_dir() -> Path:
    env = os.environ.get("BOUNTYPILOT_HOME")
    return Path(env) if env else Path.home() / ".bountypilot"


@dataclass
class ToolSettings:
    rate_limit: int  # requests (or packets) per second
    concurrency: int
    timeout: int  # wall-clock seconds for the whole phase


def _default_tools() -> dict[str, ToolSettings]:
    return {
        "subfinder": ToolSettings(rate_limit=10, concurrency=10, timeout=300),
        "dnsx": ToolSettings(rate_limit=50, concurrency=25, timeout=300),
        "httpx": ToolSettings(rate_limit=10, concurrency=10, timeout=600),
        "katana": ToolSettings(rate_limit=10, concurrency=5, timeout=900),
        "naabu": ToolSettings(rate_limit=100, concurrency=25, timeout=600),
        "ffuf": ToolSettings(rate_limit=10, concurrency=10, timeout=600),
        "nuclei": ToolSettings(rate_limit=10, concurrency=10, timeout=1800),
    }


@dataclass
class LLMSettings:
    enabled: bool = False
    base_url: str = "http://localhost:11434/v1"
    model: str = "llama3.1"
    api_key: str = ""
    timeout: int = 120
    max_items: int = 40


@dataclass
class NotifySettings:
    enabled: bool = False
    discord_webhook: str = ""
    telegram_token: str = ""
    telegram_chat_id: str = ""


@dataclass
class Config:
    tools: dict[str, ToolSettings] = field(default_factory=_default_tools)
    phases: list[str] = field(default_factory=lambda: list(DEFAULT_PHASES))
    crawl_depth: int = 2
    max_crawl_targets: int = 200
    max_endpoints: int = 20_000
    naabu_top_ports: int = 100
    ffuf_wordlist: str = ""
    ffuf_max_targets: int = 25
    nuclei_severity: list[str] = field(default_factory=lambda: ["low", "medium", "high", "critical"])
    nuclei_extra_exclude_tags: list[str] = field(default_factory=list)
    llm: LLMSettings = field(default_factory=LLMSettings)
    notify: NotifySettings = field(default_factory=NotifySettings)

    @classmethod
    def from_dict(cls, data: dict[str, Any] | None) -> Config:
        cfg = cls()
        data = data or {}
        if not isinstance(data, dict):
            raise ConfigError("config must be a YAML mapping")
        for name, vals in (data.get("tools") or {}).items():
            if name not in cfg.tools:
                raise ConfigError(f"unknown tool in config: {name}")
            t = cfg.tools[name]
            for key in ("rate_limit", "concurrency", "timeout"):
                if key in vals:
                    v = vals[key]
                    if not isinstance(v, int) or isinstance(v, bool) or v <= 0:
                        raise ConfigError(f"tools.{name}.{key} must be a positive integer")
                    setattr(t, key, v)
        if "phases" in data:
            phases = data["phases"]
            bad = [p for p in phases if p not in ALL_PHASES]
            if bad:
                raise ConfigError(f"unknown phases in config: {bad}")
            cfg.phases = list(phases)
        for key in ("crawl_depth", "max_crawl_targets", "max_endpoints", "naabu_top_ports",
                    "ffuf_max_targets"):
            if key in data:
                if not isinstance(data[key], int) or data[key] <= 0:
                    raise ConfigError(f"{key} must be a positive integer")
                setattr(cfg, key, data[key])
        if "ffuf_wordlist" in data:
            cfg.ffuf_wordlist = str(data["ffuf_wordlist"] or "")
        if "nuclei_severity" in data:
            cfg.nuclei_severity = [str(s).lower() for s in data["nuclei_severity"]]
        if "nuclei_extra_exclude_tags" in data:
            cfg.nuclei_extra_exclude_tags = [str(s) for s in data["nuclei_extra_exclude_tags"]]
        for section, target in (("llm", cfg.llm), ("notify", cfg.notify)):
            for k, v in (data.get(section) or {}).items():
                if not hasattr(target, k):
                    raise ConfigError(f"unknown option {section}.{k}")
                setattr(target, k, v)
        cfg._apply_env()
        return cfg

    def _apply_env(self) -> None:
        env = os.environ.get
        self.llm.base_url = env("BOUNTYPILOT_LLM_BASE_URL", self.llm.base_url)
        self.llm.model = env("BOUNTYPILOT_LLM_MODEL", self.llm.model)
        self.llm.api_key = env("BOUNTYPILOT_LLM_API_KEY", self.llm.api_key)
        self.notify.discord_webhook = env("BOUNTYPILOT_DISCORD_WEBHOOK", self.notify.discord_webhook)
        self.notify.telegram_token = env("BOUNTYPILOT_TELEGRAM_TOKEN", self.notify.telegram_token)
        self.notify.telegram_chat_id = env(
            "BOUNTYPILOT_TELEGRAM_CHAT_ID", self.notify.telegram_chat_id
        )

    @classmethod
    def load(cls, path: Path | None = None) -> Config:
        path = path or home_dir() / "config.yaml"
        if not path.exists():
            return cls.from_dict({})
        try:
            data = yaml.safe_load(path.read_text(encoding="utf-8"))
        except yaml.YAMLError as exc:
            raise ConfigError(f"invalid YAML in {path}: {exc}") from exc
        return cls.from_dict(data)

    def nuclei_exclude_tags(self) -> list[str]:
        tags = list(FORBIDDEN_NUCLEI_TAGS)
        for t in self.nuclei_extra_exclude_tags:
            if t not in tags:
                tags.append(t)
        return tags
