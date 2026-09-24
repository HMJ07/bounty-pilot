# Security and responsible use

## Responsible use

bounty-pilot is for **authorized** security testing only: assets that are explicitly in scope
of a bug bounty or vulnerability disclosure program you are allowed to test, or systems you
own. Testing anything else may be illegal in your jurisdiction. The authors accept no
liability for misuse.

* Always copy scope from the program's official policy, and re-check it before each campaign;
  scopes change. Use `bountypilot scope check <program> <asset>` to verify.
* Respect program rules on automation and rate limits. bounty-pilot's defaults are
  conservative; do not raise them beyond what the program allows.
* Never test out-of-scope assets, third-party services, or other users' data.
* A tool detection is a lead, not a vulnerability. Verify manually before reporting and stop
  at the minimum proof needed. Do not access, modify or retain other people's data.

## Design boundaries that limit harm

* Scope engine with default-deny; out-of-scope always wins; blocked attempts are logged.
* No exploitation, no credential guessing, no payload confirmation. Nuclei templates tagged
  `dos`, `intrusive`, `fuzz`, `bruteforce`, `default-login` are always excluded.
* Notifications contain counts only. LLM triage is optional and only reorders findings
  (with a remote endpoint, hostnames leave your machine; prefer a local model).

## Reporting a vulnerability in bounty-pilot

Please report privately through GitHub's *"Report a vulnerability"* (Security tab) on
https://github.com/HMJ07/bounty-pilot, or open a minimal issue asking for a private channel
without technical details. I aim to acknowledge within 7 days and to coordinate a fix and
disclosure timeline with you. Scope-engine bypasses (anything that lets an out-of-scope host
be treated as in scope) are treated as high severity.

## Local data

`~/.bountypilot/` (override with `BOUNTYPILOT_HOME`) holds your scan history, scopes and log.
Treat it as sensitive: it may describe private programs. Webhook and API secrets are read
from environment variables and are never written to the database.
