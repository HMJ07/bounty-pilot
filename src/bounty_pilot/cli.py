"""Command line interface: ``bountypilot``."""

from __future__ import annotations

import argparse
import logging
import platform
import sys
from pathlib import Path

from rich.console import Console
from rich.markup import escape
from rich.table import Table

from . import __version__
from .config import ALL_PHASES, Config, ConfigError, home_dir
from .diff import Diff, compute_diff
from .notify import build_summary, send
from .pipeline import PhaseError, Pipeline, parse_phases
from .report import FORMATS, ReportData, ReportError, collect_interactive, load_report_file, render
from .scope import Scope, ScopeError
from .storage import Storage
from .tools import build_tools
from .triage import triage
from .ui import print_diff, print_state

console = Console(highlight=False)
err = Console(stderr=True, highlight=False)

BANNER = (
    "bounty-pilot is for AUTHORIZED testing only: run it exclusively against assets that are "
    "explicitly in scope of a program you are permitted to test."
)


def _open_storage() -> Storage:
    return Storage(home_dir() / "history.db")


def _setup_logging(verbose: bool) -> None:
    root = logging.getLogger("bounty_pilot")
    root.setLevel(logging.DEBUG if verbose else logging.WARNING)
    root.handlers.clear()
    try:  # audit trail of everything the scope engine blocked
        home_dir().mkdir(parents=True, exist_ok=True)
        fh = logging.FileHandler(home_dir() / "bountypilot.log", encoding="utf-8")
        fh.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(name)s: %(message)s"))
        root.addHandler(fh)
    except OSError:
        pass
    root.propagate = False  # user-facing warnings are printed by the CLI itself


def _load_scope(storage: Storage, target: str) -> Scope | None:
    text = storage.get_scope_yaml(target)
    if text is None:
        err.print(f"[red]Unknown target '{escape(target)}'.[/red] Register it with "
                  "`bountypilot scope add <file.yaml>`.")
        known = storage.list_targets()
        if known:
            err.print("Registered: " + ", ".join(escape(k) for k in known))
        return None
    return Scope.from_yaml(text)


# ---- commands -----------------------------------------------------------------------
def cmd_scope(args: argparse.Namespace) -> int:
    storage = _open_storage()
    try:
        if args.scope_cmd == "add":
            path = Path(args.file)
            try:
                text = path.read_text(encoding="utf-8")
                scope = Scope.from_yaml(text)
            except OSError as exc:
                err.print(f"[red]Cannot read {escape(str(path))}: {escape(str(exc))}[/red]")
                return 2
            except ScopeError as exc:
                err.print(f"[red]Invalid scope file:[/red] {escape(str(exc))}")
                return 2
            storage.add_target(scope.program, text)
            console.print(f"Registered [bold]{escape(scope.program)}[/bold]: "
                          f"{len(scope.in_scope)} in-scope rule(s), "
                          f"{len(scope.out_of_scope)} out-of-scope rule(s).")
            console.print("Verify with: bountypilot scope check "
                          f"{escape(scope.program)} <host-or-url>")
        elif args.scope_cmd == "list":
            targets = storage.list_targets()
            if not targets:
                console.print("No targets registered yet.")
            for t in targets:
                console.print(escape(t))
        elif args.scope_cmd == "remove":
            ok = storage.remove_target(args.target)
            console.print("Removed (history deleted)." if ok else "No such target.")
            return 0 if ok else 1
        elif args.scope_cmd == "check":
            scope = _load_scope(storage, args.target)
            if scope is None:
                return 2
            d = scope.check(args.asset)
            colour = "green" if d.allowed else "red"
            console.print(f"[{colour}]{'IN SCOPE' if d.allowed else 'BLOCKED'}[/{colour}] "
                          f"{escape(args.asset)} - {escape(d.reason)}")
            return 0 if d.allowed else 1
    except ScopeError as exc:
        err.print(f"[red]Stored scope is invalid:[/red] {escape(str(exc))}")
        return 2
    finally:
        storage.close()
    return 0


def _triage_and_print(storage: Storage, cfg: Config, diff: Diff, use_llm: bool, show_all: bool) -> None:
    llm = cfg.llm if (use_llm or cfg.llm.enabled) else None
    if llm is not None:
        llm.enabled = True
    items, warn = triage(diff, llm)
    if warn:
        err.print(f"[yellow]warning:[/yellow] {escape(warn)}")
    print_diff(console, diff, items, limit=10_000 if show_all else 25)


def cmd_scan(args: argparse.Namespace) -> int:
    console.print(f"[dim]{BANNER}[/dim]")
    try:
        cfg = Config.load(Path(args.config) if args.config else None)
        phases = parse_phases(args.phases, cfg.phases)
    except (ConfigError, PhaseError) as exc:
        err.print(f"[red]{escape(str(exc))}[/red]")
        return 2
    storage = _open_storage()
    try:
        try:
            scope = _load_scope(storage, args.target)
        except ScopeError as exc:
            err.print(f"[red]Stored scope is invalid:[/red] {escape(str(exc))}")
            return 2
        if scope is None:
            return 2
        previous = storage.latest_snapshot(args.target)
        pipe = Pipeline(scope, cfg, build_tools(cfg), previous,
                        progress=lambda m: console.print(f"[dim]{escape(m)}[/dim]"))
        snap = pipe.run(phases)
        if not pipe.completed:
            err.print("[red]No phase could run.[/red] Install the missing tools "
                      "(see `bountypilot doctor`). Nothing was stored.")
            return 3
        storage.save_snapshot(snap)
        diff = compute_diff(previous, snap)
        console.print()
        _triage_and_print(storage, cfg, diff, args.llm, args.all)
        if args.notify or cfg.notify.enabled:
            for line in send(cfg.notify, build_summary(scope.program, diff, snap.run_id)):
                console.print(f"[dim]notify {escape(line)}[/dim]")
        console.print(f"\nRun #{snap.run_id} stored. Full state: bountypilot show {escape(args.target)}")
        return 0
    finally:
        storage.close()


def cmd_show(args: argparse.Namespace) -> int:
    storage = _open_storage()
    try:
        snap = (storage.get_snapshot(args.target, args.run) if args.run
                else storage.latest_snapshot(args.target))
        if snap is None:
            err.print(f"No stored runs for '{escape(args.target)}'. Run `bountypilot scan` first.")
            return 1
        print_state(console, snap, show_all=args.all)
        return 0
    finally:
        storage.close()


def cmd_diff(args: argparse.Namespace) -> int:
    storage = _open_storage()
    try:
        cfg = Config.load(Path(args.config) if args.config else None)
        new = storage.latest_snapshot(args.target)
        if new is None or new.run_id is None:
            err.print(f"No stored runs for '{escape(args.target)}'.")
            return 1
        if args.since is not None:
            old = storage.get_snapshot(args.target, args.since)
            if old is None:
                err.print(f"Run #{args.since} not found for '{escape(args.target)}'.")
                return 1
        else:
            old = storage.previous_snapshot(args.target, new.run_id)
        _triage_and_print(storage, cfg, compute_diff(old, new), args.llm, args.all)
        return 0
    except ConfigError as exc:
        err.print(f"[red]{escape(str(exc))}[/red]")
        return 2
    finally:
        storage.close()


def cmd_runs(args: argparse.Namespace) -> int:
    storage = _open_storage()
    try:
        runs = storage.list_runs(args.target)
        if not runs:
            console.print("No runs stored.")
            return 1
        t = Table(title=f"Runs for {escape(args.target)}")
        for col in ("Run", "Started (UTC)", "Phases", "Items"):
            t.add_column(col)
        for r in runs:
            t.add_row(str(r["id"]), r["started_at"], ",".join(r["phases"]), str(r["items"]))
        console.print(t)
        return 0
    finally:
        storage.close()


def cmd_report(args: argparse.Namespace) -> int:
    try:
        data: ReportData = (
            load_report_file(args.from_file) if args.from_file else collect_interactive()
        )
        text = render(data, args.format)
    except (ReportError, OSError) as exc:
        err.print(f"[red]Report error:[/red] {escape(str(exc))}")
        return 2
    except (EOFError, KeyboardInterrupt):
        err.print("\nAborted.")
        return 130
    if args.output:
        Path(args.output).write_text(text, encoding="utf-8")
        console.print(f"Report written to {escape(args.output)}")
    else:
        sys.stdout.write(text)
    return 0


def cmd_doctor(args: argparse.Namespace) -> int:
    cfg = Config()
    tools = build_tools(cfg)
    table = Table(title="External tools")
    for col in ("Tool", "Status", "Path", "Used by phase"):
        table.add_column(col)
    from .pipeline import PHASE_TOOLS

    used = {t: p for p, ts in PHASE_TOOLS.items() for t in ts}
    missing = []
    for name, tool in tools.items():
        if tool.available():
            table.add_row(name, "[green]installed[/green]", escape(tool.path() or ""), used[name])
        else:
            found = tool.path()
            status = "[red]wrong binary[/red]" if found else "[red]missing[/red]"
            table.add_row(name, status, escape(found or "-"), used[name])
            missing.append(tool)
    console.print(table)
    console.print(f"{len(tools) - len(missing)}/{len(tools)} tools available. "
                  "Missing tools only skip their phase; the rest of the pipeline still runs.")
    if missing:
        system = platform.system()
        console.print("\n[bold]Install instructions[/bold]")
        console.print("All tools are Go programs (needs Go 1.21+ from https://go.dev/dl/), or "
                      "download release binaries from each project's GitHub releases page.")
        for tool in missing:
            console.print(f"  {tool.name}: go install -v {tool.go_install}")
        if system == "Darwin":
            console.print("  macOS/Homebrew: brew install " + " ".join(t.brew for t in missing))
        elif system == "Windows":
            console.print("  Windows: use `go install` above, or scoop / release .zip binaries; "
                          "make sure %USERPROFILE%\\go\\bin is on PATH.")
        else:
            console.print("  Linux: use `go install` above and add $(go env GOPATH)/bin to PATH "
                          "(Kali/Parrot also package several of them via apt).")
        if any(t.name == "httpx" for t in missing):
            console.print("  Note: the Python 'httpx' package also installs an `httpx` command; "
                          "bounty-pilot needs ProjectDiscovery's httpx.")
    return 0


# ---- parser -------------------------------------------------------------------------
def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="bountypilot",
        description="Diff-first recon orchestrator for authorized bug bounty hunting.",
        epilog=BANNER,
    )
    p.add_argument("--version", action="version", version=f"bountypilot {__version__}")
    p.add_argument("-v", "--verbose", action="store_true", help="debug logging to the log file")
    sub = p.add_subparsers(dest="command", required=True)

    sc = sub.add_parser("scope", help="manage program scopes")
    ssub = sc.add_subparsers(dest="scope_cmd", required=True)
    a = ssub.add_parser("add", help="register/update a program's scope YAML")
    a.add_argument("file")
    ssub.add_parser("list", help="list registered targets")
    r = ssub.add_parser("remove", help="remove a target and its history")
    r.add_argument("target")
    c = ssub.add_parser("check", help="test whether a host/URL/IP is in scope")
    c.add_argument("target")
    c.add_argument("asset")
    sc.set_defaults(func=cmd_scope)

    s = sub.add_parser("scan", help="run the pipeline and show what changed")
    s.add_argument("target")
    s.add_argument("--phases", help=f"comma list from: {', '.join(ALL_PHASES)}")
    s.add_argument("--config", help="path to a config.yaml")
    s.add_argument("--llm", action="store_true", help="re-rank with the configured LLM")
    s.add_argument("--notify", action="store_true", help="send a count-only summary")
    s.add_argument("--all", action="store_true", help="do not truncate the ranked list")
    s.set_defaults(func=cmd_scan)

    sh = sub.add_parser("show", help="show the latest full known state")
    sh.add_argument("target")
    sh.add_argument("--run", type=int, help="show a specific run id")
    sh.add_argument("--all", action="store_true")
    sh.set_defaults(func=cmd_show)

    d = sub.add_parser("diff", help="show what changed (default: since the previous run)")
    d.add_argument("target")
    d.add_argument("--since", type=int, help="compare against this run id")
    d.add_argument("--config")
    d.add_argument("--llm", action="store_true")
    d.add_argument("--all", action="store_true")
    d.set_defaults(func=cmd_diff)

    ru = sub.add_parser("runs", help="list stored runs")
    ru.add_argument("target")
    ru.set_defaults(func=cmd_runs)

    rp = sub.add_parser("report", help="render a report for a MANUALLY confirmed finding")
    rp.add_argument("--from", dest="from_file", help="YAML/JSON input file (non-interactive)")
    rp.add_argument("--format", choices=FORMATS, default="hackerone")
    rp.add_argument("-o", "--output", help="write Markdown to this file")
    rp.set_defaults(func=cmd_report)

    dr = sub.add_parser("doctor", help="check which external tools are installed")
    dr.set_defaults(func=cmd_doctor)
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    _setup_logging(args.verbose)
    try:
        return int(args.func(args))
    except KeyboardInterrupt:
        err.print("\nInterrupted.")
        return 130


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
