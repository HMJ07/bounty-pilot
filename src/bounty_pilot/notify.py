"""Optional Discord / Telegram summaries. Off by default; counts only, never technical details."""

from __future__ import annotations

import json
import urllib.error
import urllib.request
from collections.abc import Callable
from typing import Any
from urllib.parse import urlsplit

from .config import NotifySettings
from .diff import Diff

Post = Callable[[str, dict[str, Any], float], None]

_DISCORD_HOSTS = ("discord.com", "discordapp.com")


class NotifyError(Exception):
    pass


def build_summary(target: str, diff: Diff, run_id: int | None) -> str:
    """A short, count-only message. Hostnames, URLs and finding names are never included."""
    c = diff.counts()
    label = f"bounty-pilot: '{target}'" + (f" run #{run_id}" if run_id else "")
    if diff.is_baseline:
        return f"{label} - baseline scan stored. Run `bountypilot show {target}` for details."
    parts = []
    if c["new_subdomains"]:
        parts.append(f"{c['new_subdomains']} new subdomain(s)")
    if c["newly_live"]:
        parts.append(f"{c['newly_live']} newly live service(s)")
    if c["new_endpoints"]:
        parts.append(f"{c['new_endpoints']} new endpoint(s)")
    if c["new_ports"]:
        parts.append(f"{c['new_ports']} new open port(s)")
    if c["new_findings"]:
        sev: dict[str, int] = {}
        for f in diff.new_findings:
            sev[f.severity] = sev.get(f.severity, 0) + 1
        order = ["critical", "high", "medium", "low", "info"]
        detail = ", ".join(f"{sev[s]} {s}" for s in order if s in sev)
        parts.append(f"{c['new_findings']} new finding(s) ({detail})")
    if not parts:
        return f"{label} - no new changes."
    return f"{label} - " + ", ".join(parts) + f". Run `bountypilot diff {target}` for details."


def default_post(url: str, payload: dict[str, Any], timeout: float) -> None:
    req = urllib.request.Request(  # noqa: S310 - https enforced by validate_*
        url,
        data=json.dumps(payload).encode(),
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout):  # noqa: S310
            return
    except (urllib.error.URLError, OSError) as exc:
        # Deliberately do not echo the URL: it contains a secret (webhook token / bot token).
        raise NotifyError(f"request failed ({type(exc).__name__})") from exc


def validate_discord(url: str) -> None:
    parts = urlsplit(url)
    if parts.scheme != "https" or (parts.hostname or "") not in _DISCORD_HOSTS:
        raise NotifyError("Discord webhook must be an https://discord.com/api/webhooks/... URL")


def send(settings: NotifySettings, text: str, post: Post | None = None) -> list[str]:
    """Send ``text`` to every configured channel. Returns human-readable per-channel results."""
    post = post or default_post
    results: list[str] = []
    if settings.discord_webhook:
        try:
            validate_discord(settings.discord_webhook)
            post(settings.discord_webhook, {"content": text, "allowed_mentions": {"parse": []}}, 15)
            results.append("discord: sent")
        except NotifyError as exc:
            results.append(f"discord: failed - {exc}")
    if settings.telegram_token and settings.telegram_chat_id:
        try:
            url = f"https://api.telegram.org/bot{settings.telegram_token}/sendMessage"
            post(url, {"chat_id": settings.telegram_chat_id, "text": text}, 15)
            results.append("telegram: sent")
        except NotifyError as exc:
            results.append(f"telegram: failed - {exc}")
    if not results:
        results.append("no notification channel configured")
    return results
