"""Normalized data models shared by every tool wrapper, the storage layer and the diff engine."""

from __future__ import annotations

import dataclasses
from dataclasses import dataclass, field
from typing import Any, TypeVar

SEVERITIES = ("info", "low", "medium", "high", "critical")
_SEV_RANK = {s: i for i, s in enumerate(SEVERITIES)}

T = TypeVar("T")


def severity_rank(severity: str) -> int:
    """Numeric rank of a severity string (unknown -> -1, below info)."""
    return _SEV_RANK.get((severity or "").lower(), -1)


def normalize_severity(severity: object) -> str:
    s = str(severity or "").strip().lower()
    return s if s in _SEV_RANK else "info"


class _Model:
    def to_dict(self) -> dict[str, Any]:
        return dataclasses.asdict(self)  # type: ignore[call-overload]

    @classmethod
    def from_dict(cls: type[T], data: dict[str, Any]) -> T:
        names = {f.name for f in dataclasses.fields(cls)}  # type: ignore[arg-type]
        return cls(**{k: v for k, v in data.items() if k in names})  # type: ignore[call-arg]


@dataclass
class Subdomain(_Model):
    host: str
    source: str = ""
    ips: list[str] = field(default_factory=list)
    resolves: bool | None = None  # None = never checked

    @property
    def key(self) -> str:
        return self.host


@dataclass
class HttpService(_Model):
    url: str
    host: str
    status_code: int | None = None
    title: str = ""
    server: str = ""
    technologies: list[str] = field(default_factory=list)
    content_length: int | None = None
    ip: str = ""

    @property
    def key(self) -> str:
        return self.url


@dataclass
class Endpoint(_Model):
    url: str
    host: str
    method: str = "GET"
    source: str = ""

    @property
    def key(self) -> str:
        return f"{self.method} {self.url}"


@dataclass
class OpenPort(_Model):
    host: str
    port: int
    ip: str = ""

    @property
    def key(self) -> str:
        return f"{self.host}:{self.port}"


@dataclass
class Finding(_Model):
    template_id: str
    name: str
    severity: str
    host: str
    matched_at: str
    description: str = ""
    tags: list[str] = field(default_factory=list)

    @property
    def key(self) -> str:
        return f"{self.template_id}@{self.matched_at}"


@dataclass
class Snapshot:
    """Everything known about a target at the end of one run."""

    target: str
    run_id: int | None = None
    started_at: str = ""
    finished_at: str = ""
    phases: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    subdomains: list[Subdomain] = field(default_factory=list)
    services: list[HttpService] = field(default_factory=list)
    endpoints: list[Endpoint] = field(default_factory=list)
    ports: list[OpenPort] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)

    def live_hosts(self) -> set[str]:
        return {s.host for s in self.services}
