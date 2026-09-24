# bounty-pilot

[![CI](https://github.com/HMJ07/bounty-pilot/actions/workflows/ci.yml/badge.svg)](https://github.com/HMJ07/bounty-pilot/actions/workflows/ci.yml)
[![Python 3.10+](https://img.shields.io/badge/python-3.10%2B-blue.svg)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![Ruff](https://img.shields.io/badge/lint-ruff-261230.svg)](https://github.com/astral-sh/ruff)
![Scope-first](https://img.shields.io/badge/safety-scope--first-critical)
![No exploitation](https://img.shields.io/badge/exploitation-never-red)

**A diff-first, scope-first recon "brain" for authorized bug bounty hunting.**
bounty-pilot orchestrates the industry-standard recon tools (subfinder, dnsx, httpx, katana,
naabu, ffuf, nuclei), remembers every scan in a local SQLite database, and tells you **only
what changed since last time**, ranked by what is worth investigating first. When you have
manually confirmed something real, it turns your notes into a clean HackerOne/Bugcrowd-style
report.

`bug-bounty` `recon` `security-tools` `osint` `pentesting` `cli` `python`

---

## Why: the diff-first philosophy

Fresh, unreported bugs live where things *just changed*: a staging host that appeared
yesterday, an admin panel that went from 403 to 200, a new endpoint after a deploy, a new
nuclei hit on a host that was clean last week. Every hunter runs the same tools on the same
targets; the ones who see the delta first win.

One-shot scanners answer "what exists?" and dump thousands of lines every time. bounty-pilot
answers **"what is new or different since my last run, and what should I look at first?"**

```
run #1  ->  baseline snapshot stored
run #2  ->  diff vs run #1: 1 new subdomain, 1 newly live service, 2 new endpoints, 1 new finding
run #3  ->  "No changes since run #2."
```

## What this is / what this is NOT

**bounty-pilot is**

* an orchestration layer that drives external recon tools you install yourself,
* a scope enforcement engine that sits in front of *every* operation,
* a history + diff + triage layer, and a report formatter for findings you verified.

**bounty-pilot is NOT**

* an exploitation framework. **It never exploits anything**, never confirms a vulnerability
  with payloads, never brute-forces credentials and never fuzzes parameters. There is no
  "auto-exploit" or "auto-confirm" module and there never will be. Nuclei's own
  template-based detection is the ceiling of what runs automatically, and nuclei templates
  tagged `dos`, `intrusive`, `fuzz`, `bruteforce` and `default-login` are always excluded
  (this cannot be configured away).
* a tool for unauthorized testing. Use it **only** against assets explicitly in scope of a
  program you are allowed to test. Unauthorized scanning can be illegal. See
  [SECURITY.md](SECURITY.md).
* a report *generator* for raw detections. A nuclei match is a lead, not a vulnerability.
  `bountypilot report` only formats what **you** entered after manual verification.
* a replacement for the tools it drives, or for AutoBugBounty (see below).

## Credit and relationship to AutoBugBounty

This project was inspired by
[AutoBugBounty](https://github.com/WaterRessistan/AutoBugBounty), a solid open-source Bash
tool that chains subfinder/httpx/katana/ffuf/naabu/nuclei into a one-shot recon scan with
scope filtering. bounty-pilot is **complementary, not a competitor or rewrite**: it
targets the same class of tools but adds the pieces a one-shot scan does not have: persistent
history and diffing, prioritization of what changed, optional LLM-assisted triage, report
formatting and notifications. If a single fire-and-forget scan is what you need,
AutoBugBounty is a great choice. If you scan the same programs repeatedly and want to see
only what is new, bounty-pilot is built for that.

## Architecture

```
                       +-----------------------------------------+
                       |             bountypilot CLI             |
                       | scope | scan | show | diff | report | doctor
                       +-------------------+---------------------+
                                           |
                 +-------------------------v--------------------------+
                 |  Pipeline (phases, timeouts, degraded-mode skips)  |
                 +---+-------------------+----------------------+-----+
                     |                   |                      |
          +----------v---------+   +-----v---------+    +-------v---------+
          |   SCOPE ENGINE     |   |  Storage      |    |  Diff + Triage  |
          |  in_scope / out_of |   |  SQLite       |    |  heuristic rank |
          |  scope, default    |   |  snapshots    |    |  (+ optional    |
          |  deny, logs blocks |   |  per run      |    |   LLM re-rank)  |
          +----------+---------+   +---------------+    +--------+--------+
                     | every input AND output                    |
                     v is filtered                               v
   +---------------------------------------------+      +--------------------+
   | tools/  thin wrappers (argument lists,      |      | Report renderer    |
   | rate limits, timeouts, JSON -> models)      |      | Notifications      |
   +--+-------+------+-------+------+-----+------+      | (counts only)      |
      |       |      |       |      |     |             +--------------------+
  subfinder  dnsx  httpx  katana  naabu  ffuf  nuclei      <- external Go tools,
                                                            installed by you
```

Phases: `subdomains` (subfinder + dnsx) -> `http` (httpx) -> `crawl` (katana) -> `ports`
(naabu, opt-in) -> `fuzz` (ffuf content discovery, opt-in, needs a wordlist) -> `nuclei`.
Default phases: `subdomains,http,crawl,nuclei`.

## Install

```bash
git clone https://github.com/HMJ07/bounty-pilot
cd bounty-pilot
pip install -e .            # Python 3.10+, core deps: PyYAML, rich
bountypilot doctor          # shows which external tools are installed / missing
```

> **Windows:** if `bountypilot` is "not recognized" after installing, pip put the script in a
> folder that is not on your `PATH`. Use `python -m bounty_pilot doctor` instead (works
> everywhere), or add the Scripts folder pip printed to your `PATH`.

The external tools are Go programs from ProjectDiscovery (and ffuf). Install Go 1.21+ from
<https://go.dev/dl/>, then:

```bash
go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install -v github.com/projectdiscovery/dnsx/cmd/dnsx@latest
go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest
go install -v github.com/projectdiscovery/katana/cmd/katana@latest
go install -v github.com/projectdiscovery/naabu/v2/cmd/naabu@latest
go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
go install -v github.com/ffuf/ffuf/v2@latest
```

Make sure `$(go env GOPATH)/bin` is on your `PATH` (Windows: `%USERPROFILE%\go\bin`). macOS
users can `brew install subfinder dnsx httpx katana naabu nuclei ffuf`; release binaries are
also available on each project's GitHub releases page. Run `nuclei -update-templates` once.

> **Heads-up:** the Python package `httpx` installs a CLI also called `httpx`.
> bounty-pilot verifies it found ProjectDiscovery's and `bountypilot doctor` flags a
> "wrong binary".

**You do not need all of them.** bounty-pilot runs in a degraded-but-useful mode: a phase
whose tool is missing is skipped with a clear warning (and the install command), and the rest
of the pipeline continues. The test suite and CI exercise exactly this path.

## Quick start

```bash
# 1. Register the program's scope (copy it verbatim from the program policy)
bountypilot scope add examples/scope/example-program.yaml

# 2. Sanity-check the scope engine BEFORE scanning anything
bountypilot scope check example-corp https://www.example.com/login   # IN SCOPE
bountypilot scope check example-corp admin.example.com               # BLOCKED

# 3. Scan. First run = baseline. Later runs show only what changed.
bountypilot scan example-corp
bountypilot scan example-corp --phases subdomains,http,nuclei

# 4. Explore
bountypilot show example-corp          # full latest state
bountypilot diff example-corp          # what changed since the previous run
bountypilot diff example-corp --since 3
bountypilot runs example-corp

# 5. After you MANUALLY confirmed a real issue
bountypilot report                                            # interactive
bountypilot report --from examples/reports/idor-invoices.yaml --format hackerone -o report.md
```

### Example session (fictional program, abridged)

```console
$ bountypilot scan acme
bounty-pilot is for AUTHORIZED testing only: run it exclusively against assets
that are explicitly in scope of a program you are permitted to test.
phase: subdomains
phase: http
phase: crawl
phase: nuclei
[warn] 2 item(s) were blocked by the scope engine (see logs)

Baseline run. No earlier snapshot exists, so everything below is 'new'. From
the next run on, only real changes will be highlighted.
41 new subdomains, 27 newly live, 1180 new endpoints, 3 new findings
Run #1 stored. Full state: bountypilot show acme

$ bountypilot scan acme            # a week later
phase: subdomains
phase: http
phase: crawl
phase: nuclei
Changes since run #1 (now run #2)
1 new subdomains, 1 newly live, 2 new endpoints, 1 new findings, 1 changed services
                              Worth investigating first
+---+-------+----------+------------------------------------+---------------------------+
| # | Score | Type     | What                               | Why                       |
+---+-------+----------+------------------------------------+---------------------------+
| 1 |    95 | service  | https://admin-staging.acme.com     | new host; admin/internal/ |
|   |       |          | (HTTP 401) [Nginx]                 | staging-style hostname;   |
|   |       |          |                                    | title 'Login' suggests a  |
|   |       |          |                                    | login/admin surface;      |
|   |       |          |                                    | returned 401              |
| 2 |    90 | finding  | [high] Git Config Exposure @       | nuclei template git-config|
|   |       |          | https://www.acme.com/.git/config   | matched; pattern match    |
|   |       |          |                                    | only - verify manually    |
| 3 |    55 | endpoint | https://www.acme.com/dl?file=x     | new endpoint with an      |
|   |       |          |                                    | input-handling parameter  |
| 4 |    40 | change   | https://www.acme.com: technologies | technology stack changed  |
|   |       |          | 'Nginx' -> 'Nginx, PHP'            | - possible deploy         |
+---+-------+----------+------------------------------------+---------------------------+
Resolved findings: 1
  - Old Thing @ https://old.acme.com/x

Run #2 stored. Full state: bountypilot show acme

$ bountypilot scan acme
No changes since run #2.
```

## Scope file format

One YAML file per program ([`examples/scope/example-program.yaml`](examples/scope/example-program.yaml)):

```yaml
program: example-corp            # name you use on the CLI
platform: hackerone              # informational
in_scope:
  - "*.example.com"              # any subdomain at any depth (NOT example.com itself)
  - "example.com"                # exact host
  - "203.0.113.0/24"             # CIDR (IPv4/IPv6)
out_of_scope:                    # ALWAYS wins over in_scope
  - "admin.example.com"
  - "*.admin.example.com"        # an exact entry does not cover children: add the wildcard too
  - "203.0.113.99"
```

Rules of the engine (all covered by tests in `tests/test_scope.py`):

1. **Default deny.** Anything not matched by an `in_scope` rule is blocked.
2. **Out-of-scope always wins**, regardless of order or how specific the in-scope rule is.
3. `example.com` matches only that host; `*.example.com` matches subdomains at any depth but
   **not** the apex; `evilexample.com` and `example.com.evil.net` never match.
4. IPs are matched only by IP/CIDR rules and hostnames only by domain rules; IPv4-mapped IPv6
   is normalized; obfuscated IPs (`2130706433`, `0x7f.1`) do not match anything.
5. Ambiguous targets are **blocked**: userinfo (`good.com@evil.com`), backslashes,
   whitespace/control characters, malformed ports, wildcard characters in a target.
6. Ports, paths and schemes are ignored; the decision is made on the host.
7. Dangerous definitions are rejected at registration: `*`, `*.com`, mid-string wildcards,
   CIDRs broader than `/16` (IPv4) or `/48` (IPv6), CIDRs with host bits set.
8. Every block is logged (`~/.bountypilot/bountypilot.log`) and counted in the run summary.

The check happens **before** a request is made: inputs to every tool are filtered, tools are
told to stay on the host they were given (katana runs with `-fs fqdn`, httpx does not follow
redirects), and outputs are filtered again. Caveat worth knowing: scope is decided by
*name/IP literal*, not by DNS resolution, and CIDR ranges act as filters only (they are not
expanded into scan targets; list single hosts or let discovery find them).

## How the diff works

Every run stores an immutable snapshot (subdomains, live services, endpoints, open ports,
nuclei findings). The diff against the previous run reports:

| Change | Meaning |
|---|---|
| new / removed subdomains | hosts appearing in or vanishing from passive sources |
| newly live | a host that had **no** live HTTP service before now has one (dead -> alive) |
| new services | a new URL/port on a host that was already live |
| changed services | status code, title, server or **technology** changes on an existing URL |
| new endpoints | crawled/discovered URLs (method + URL) not seen before |
| new / closed ports | naabu results |
| new / resolved findings | nuclei matches keyed by template + matched URL |

Robustness details: phases you did not run (or whose tool was missing) are **carried forward**
from the previous snapshot, so `--phases nuclei` does not make everything else look "new"
next time; a timed-out tool's partial output is merged rather than replacing history; a tool
that crashes with no output never wipes existing data.

## Triage: heuristic first, LLM optional

The rule-based ranker is always on and needs nothing configured. Order:
critical/high nuclei findings > new admin/internal/staging/dev-sounding hostnames and
newly-live services (boosted by login/admin titles and 401/403) > medium findings, newly
exposed sensitive ports (Redis, SSH, DBs...) and endpoints with input-handling parameters >
technology changes > low/info findings and everything else.

Optionally re-rank with an LLM through any OpenAI-compatible API (Ollama by default):

```bash
export BOUNTYPILOT_LLM_BASE_URL=http://localhost:11434/v1   # default
export BOUNTYPILOT_LLM_MODEL=llama3.1
bountypilot scan acme --llm
```

The LLM can only **reorder** items the heuristic produced and rewrite their one-line
rationale. Unknown ids are ignored, nothing is dropped, nothing is executed, and a failing or
garbage-emitting model falls back to the heuristic order with a warning. Titles/URLs from
scanned sites are sent as quoted, explicitly untrusted data (prompt-injection hardening).
With a **remote** endpoint your hostnames leave your machine; use a local model for
sensitive programs.

## Politeness and rate limiting

Every tool call gets a conservative rate limit and concurrency cap and a hard wall-clock
timeout (a hung tool is killed; its partial output is still used):

| Tool | rate limit | concurrency | timeout |
|---|---|---|---|
| subfinder | 10/s | 10 | 300 s |
| dnsx | 50/s | 25 | 300 s |
| httpx | 10 req/s | 10 | 600 s |
| katana | 10 req/s | 5 | 900 s |
| naabu | 100 pkt/s, top 100 ports | 25 | 600 s |
| ffuf | 10 req/s | 10 | 600 s |
| nuclei | 10 req/s | 10 | 1800 s |

This is both an ethical requirement (do not degrade a program's infrastructure, and follow
its automation rules) and a practical one (avoid tripping WAF/IDS or getting your IP
banned). Tune in `~/.bountypilot/config.yaml`; check the program's policy before raising
anything:

```yaml
tools:
  httpx: {rate_limit: 5, concurrency: 5, timeout: 900}
phases: [subdomains, http, crawl, nuclei]
nuclei_severity: [medium, high, critical]
nuclei_extra_exclude_tags: [tech]     # you can add exclusions, never remove the built-in ones
ffuf_wordlist: /path/to/wordlist.txt  # required for the opt-in `fuzz` phase
llm: {enabled: false}
notify: {enabled: false}
```

## Reports

`bountypilot report` (interactive) or `--from file.yaml|json` renders Markdown with a
Summary / Steps to Reproduce / Impact / Remediation skeleton in HackerOne style, or
`--format bugcrowd` for Bugcrowd's layout. Severity is derived from a CVSS score if you do
not set it. Two fictional examples show the quality bar:

* [`examples/reports/idor-invoices.yaml`](examples/reports/idor-invoices.yaml) -> [rendered](examples/reports/idor-invoices.md)
* [`examples/reports/subdomain-takeover.yaml`](examples/reports/subdomain-takeover.yaml) -> [rendered](examples/reports/subdomain-takeover.md)

## Notifications (off by default)

Optional Discord and/or Telegram summary after a scan, enabled with `--notify` or
`notify.enabled: true`. Secrets come from the environment:

```bash
export BOUNTYPILOT_DISCORD_WEBHOOK=https://discord.com/api/webhooks/...
export BOUNTYPILOT_TELEGRAM_TOKEN=...   BOUNTYPILOT_TELEGRAM_CHAT_ID=...
```

Messages contain **counts only** ("2 new subdomain(s), 1 new finding(s) (1 high). Run
`bountypilot diff acme` for details"): never hostnames, URLs or finding names.

## Development

```bash
pip install -e ".[dev]"
pytest -q
ruff check .
```

The suite (200+ tests) covers the scope engine (wildcards, CIDR, precedence, parser edge
cases), the diff engine, every tool parser, storage round-trips, triage, reports, degraded
mode and end-to-end CLI runs. It performs **no** real subprocess or network calls; an autouse
fixture fails the test if one is attempted. See [CONTRIBUTING.md](CONTRIBUTING.md).

## License

MIT, see [LICENSE](LICENSE). Use responsibly: [SECURITY.md](SECURITY.md).
