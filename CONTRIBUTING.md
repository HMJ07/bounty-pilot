# Contributing to bounty-pilot

Thanks for helping! Please read the two hard rules first.

## Hard rules (PRs that break these will not be merged)

1. **Scope first.** Every new tool wrapper must filter its inputs *and* outputs through
   `Scope` (see `tools/httpx.py` for the pattern) and must never contact anything the scope
   engine has not allowed. Any change to `scope.py` needs new tests, especially for
   precedence (out-of-scope wins) and parsing edge cases.
2. **No exploitation.** bounty-pilot detects and pattern-matches; it never exploits, confirms
   by payload, brute-forces credentials or fuzzes parameters. Do not add "auto-exploit" /
   "auto-confirm" modules, and do not remove entries from `FORBIDDEN_NUCLEI_TAGS`.

## Development setup

```bash
git clone https://github.com/HMJ07/bounty-pilot && cd bounty-pilot
python -m venv .venv && source .venv/bin/activate      # Windows: .venv\Scripts\activate
pip install -e ".[dev]"
pytest -q
ruff check .
```

The test suite never runs a real security tool and never touches the network. An autouse
fixture in `tests/conftest.py` makes any accidental `subprocess.run` or `urlopen` fail the
test. Keep it that way: mock with the `FakeRunner` helper.

## Adding a tool wrapper

1. Subclass `Tool` in `src/bounty_pilot/tools/<name>.py`: set `name`, `binary`, `go_install`.
2. Build the command as an **argument list** (never `shell=True`, never string-joined),
   pass targets on stdin, apply the configured rate limit / concurrency.
3. Write a pure `parse(stdout)` that returns normalized models and tolerates garbage lines.
4. Filter inputs with `scope.filter(...)` and outputs with `scope.is_allowed(...)`.
5. Register it in `tools/__init__.py`, add defaults in `config.py`, wire a phase in
   `pipeline.py`, and add parser + scope-filtering tests.

## Style

* Python 3.10+, `ruff` clean (`ruff check .`), type hints on public functions.
* Keep the core dependency-light (PyYAML + rich). Prefer the standard library.
* Small, focused commits with clear messages.

## Reporting bugs / ideas

Open an issue. For security problems in bounty-pilot itself see [SECURITY.md](SECURITY.md).
