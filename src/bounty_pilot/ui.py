"""Terminal rendering (rich). All target-controlled strings are markup-escaped."""

from __future__ import annotations

from rich.console import Console
from rich.markup import escape
from rich.table import Table

from .diff import Diff
from .models import Snapshot, severity_rank
from .triage.heuristic import TriageItem

_SEV_STYLE = {"critical": "bold red", "high": "red", "medium": "yellow", "low": "cyan", "info": "dim"}


def _e(value: object) -> str:
    return escape(str(value))


def print_diff(console: Console, diff: Diff, items: list[TriageItem], limit: int = 25) -> None:
    if diff.is_baseline:
        console.print(
            "[bold]Baseline run.[/bold] No earlier snapshot exists, so everything below is "
            "'new'. From the next run on, only real changes will be highlighted."
        )
    elif diff.is_empty():
        console.print(f"[green]No changes since run #{diff.old_run_id}.[/green]")
        return
    else:
        console.print(f"[bold]Changes since run #{diff.old_run_id}[/bold] (now run #{diff.new_run_id})")

    c = diff.counts()
    summary = ", ".join(f"{v} {k.replace('_', ' ')}" for k, v in c.items() if v)
    if summary:
        console.print(summary)

    if items:
        table = Table(title="Worth investigating first", show_lines=False)
        table.add_column("#", justify="right")
        table.add_column("Score", justify="right")
        table.add_column("Type")
        table.add_column("What")
        table.add_column("Why")
        for n, it in enumerate(items[:limit], start=1):
            why = _e(it.rationale) + (" [dim](llm)[/dim]" if it.source == "llm" else "")
            table.add_row(str(n), str(it.score), it.category, _e(it.subject), why)
        console.print(table)
        if len(items) > limit:
            console.print(f"[dim]... {len(items) - limit} more (use --all to list everything)[/dim]")

    if diff.resolved_findings:
        console.print(f"[green]Resolved findings:[/green] {len(diff.resolved_findings)}")
        for f in diff.resolved_findings[:10]:
            console.print(f"  - {_e(f.name)} @ {_e(f.matched_at)}")
    if diff.gone_dead:
        console.print(f"[yellow]Services no longer live:[/yellow] {len(diff.gone_dead)}")
        for s in diff.gone_dead[:10]:
            console.print(f"  - {_e(s.url)}")
    if diff.removed_subdomains:
        console.print(f"[dim]Subdomains not seen this run:[/dim] {len(diff.removed_subdomains)}")
    if diff.closed_ports:
        console.print(f"[dim]Ports no longer open:[/dim] {len(diff.closed_ports)}")


def print_state(console: Console, snap: Snapshot, show_all: bool = False, limit: int = 30) -> None:
    console.print(
        f"[bold]{_e(snap.target)}[/bold] - run #{snap.run_id} at {_e(snap.started_at)} "
        f"(phases: {_e(', '.join(snap.phases) or 'none')})"
    )
    for w in snap.warnings:
        console.print(f"[yellow]warning:[/yellow] {_e(w)}")

    def cap(seq):
        return seq if show_all else seq[:limit]

    if snap.findings:
        t = Table(title=f"Findings ({len(snap.findings)})")
        for col in ("Severity", "Name", "Matched at", "Template"):
            t.add_column(col)
        for f in cap(sorted(snap.findings, key=lambda x: -severity_rank(x.severity))):
            style = _SEV_STYLE.get(f.severity, "")
            t.add_row(f"[{style}]{f.severity}[/{style}]" if style else f.severity,
                      _e(f.name), _e(f.matched_at), _e(f.template_id))
        console.print(t)
    if snap.services:
        t = Table(title=f"Live HTTP services ({len(snap.services)})")
        for col in ("URL", "Status", "Title", "Tech"):
            t.add_column(col)
        for s in cap(sorted(snap.services, key=lambda x: x.url)):
            t.add_row(_e(s.url), str(s.status_code or ""), _e(s.title[:50]),
                      _e(", ".join(s.technologies[:4])))
        console.print(t)
    if snap.ports:
        t = Table(title=f"Open ports ({len(snap.ports)})")
        t.add_column("Host")
        t.add_column("Port", justify="right")
        for p in cap(sorted(snap.ports, key=lambda x: (x.host, x.port))):
            t.add_row(_e(p.host), str(p.port))
        console.print(t)
    console.print(f"Subdomains: {len(snap.subdomains)}   Endpoints: {len(snap.endpoints)}")
    if snap.subdomains:
        for s in cap(sorted(snap.subdomains, key=lambda x: x.host)):
            state = {True: "resolves", False: "no DNS", None: "unchecked"}[s.resolves]
            console.print(f"  {_e(s.host)} [dim]({state})[/dim]")
    if snap.endpoints:
        console.print("Endpoints:")
        for e in cap(sorted(snap.endpoints, key=lambda x: x.url)):
            console.print(f"  {_e(e.method)} {_e(e.url)}")
    if not show_all and max(len(snap.subdomains), len(snap.endpoints), len(snap.services),
                            len(snap.findings)) > limit:
        console.print(f"[dim](lists truncated to {limit}; use --all for everything)[/dim]")
