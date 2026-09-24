"""Diff engine: what changed between two snapshots of the same target."""

from __future__ import annotations

from dataclasses import dataclass, field

from .models import Endpoint, Finding, HttpService, OpenPort, Snapshot, Subdomain


@dataclass
class ServiceChange:
    url: str
    host: str
    field: str  # status_code | title | server | technologies
    old: str
    new: str


@dataclass
class Diff:
    target: str
    old_run_id: int | None
    new_run_id: int | None
    is_baseline: bool = False  # True when there is no earlier snapshot to compare with
    new_subdomains: list[Subdomain] = field(default_factory=list)
    removed_subdomains: list[Subdomain] = field(default_factory=list)
    newly_live: list[HttpService] = field(default_factory=list)  # host had no live service before
    gone_dead: list[HttpService] = field(default_factory=list)  # host lost all live services
    new_services: list[HttpService] = field(default_factory=list)  # new URL on an already-live host
    changed_services: list[ServiceChange] = field(default_factory=list)
    new_endpoints: list[Endpoint] = field(default_factory=list)
    new_ports: list[OpenPort] = field(default_factory=list)
    closed_ports: list[OpenPort] = field(default_factory=list)
    new_findings: list[Finding] = field(default_factory=list)
    resolved_findings: list[Finding] = field(default_factory=list)

    def counts(self) -> dict[str, int]:
        return {
            "new_subdomains": len(self.new_subdomains),
            "newly_live": len(self.newly_live),
            "new_services": len(self.new_services),
            "changed_services": len(self.changed_services),
            "new_endpoints": len(self.new_endpoints),
            "new_ports": len(self.new_ports),
            "new_findings": len(self.new_findings),
            "resolved_findings": len(self.resolved_findings),
        }

    def is_empty(self) -> bool:
        return not any(
            (self.new_subdomains, self.removed_subdomains, self.newly_live, self.gone_dead,
             self.new_services, self.changed_services, self.new_endpoints, self.new_ports,
             self.closed_ports, self.new_findings, self.resolved_findings)
        )


def _by_key(items):
    return {i.key: i for i in items}


def _svc_fields(s: HttpService) -> dict[str, str]:
    return {
        "status_code": "" if s.status_code is None else str(s.status_code),
        "title": s.title,
        "server": s.server,
        "technologies": ", ".join(sorted(s.technologies)),
    }


def compute_diff(old: Snapshot | None, new: Snapshot) -> Diff:
    """Compare ``new`` against ``old`` (None means first run: everything is new)."""
    empty = Snapshot(target=new.target)
    base = old or empty
    d = Diff(target=new.target, old_run_id=old.run_id if old else None,
             new_run_id=new.run_id, is_baseline=old is None)

    o_sub, n_sub = _by_key(base.subdomains), _by_key(new.subdomains)
    d.new_subdomains = [n_sub[k] for k in sorted(n_sub.keys() - o_sub.keys())]
    d.removed_subdomains = [o_sub[k] for k in sorted(o_sub.keys() - n_sub.keys())]

    o_live, n_live = base.live_hosts(), new.live_hosts()
    o_svc, n_svc = _by_key(base.services), _by_key(new.services)
    for k in sorted(n_svc):
        svc = n_svc[k]
        if svc.host not in o_live:
            d.newly_live.append(svc)
        elif k not in o_svc:
            d.new_services.append(svc)
        else:
            before, after = _svc_fields(o_svc[k]), _svc_fields(svc)
            for fld in before:
                if before[fld] != after[fld]:
                    d.changed_services.append(
                        ServiceChange(svc.url, svc.host, fld, before[fld], after[fld])
                    )
    d.gone_dead = [o_svc[k] for k in sorted(o_svc) if o_svc[k].host not in n_live]

    o_ep, n_ep = _by_key(base.endpoints), _by_key(new.endpoints)
    d.new_endpoints = [n_ep[k] for k in sorted(n_ep.keys() - o_ep.keys())]

    o_pt, n_pt = _by_key(base.ports), _by_key(new.ports)
    d.new_ports = [n_pt[k] for k in sorted(n_pt.keys() - o_pt.keys())]
    d.closed_ports = [o_pt[k] for k in sorted(o_pt.keys() - n_pt.keys())]

    o_f, n_f = _by_key(base.findings), _by_key(new.findings)
    d.new_findings = [n_f[k] for k in sorted(n_f.keys() - o_f.keys())]
    d.resolved_findings = [o_f[k] for k in sorted(o_f.keys() - n_f.keys())]
    return d
