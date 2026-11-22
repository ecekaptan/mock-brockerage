#!/usr/bin/env python3
"""A small reference engine that runs the Sigma rules in detections/rules/
over MiniApp's JSON security logs and prints alerts.

This is not a SIEM. In production the same .yml rules would be converted with
pySigma / sigma-cli for Elastic, Splunk or Wazuh. This file exists so the
detection logic can be run, read and tested locally without any of that.

Usage:
    python detect.py samples/main.jsonl
    docker compose logs api --no-log-prefix | python detect.py -
    python detect.py --json samples/vulnerable.jsonl

Supported Sigma subset (anything else raises an error instead of silently
not matching):
  * detection: selections as maps (AND of fields) or lists of maps (OR); a
    list of values means OR (or AND with |all); `null` means "field absent".
  * modifiers: contains, startswith, endswith, re, gt, gte, lt, lte, all,
    fieldref (compare with another field of the same event).
  * condition: selection names joined with and / or / not and parentheses.
  * correlation: event_count, value_count (conditions gt / gte), temporal,
    temporal_ordered; group-by; timespan in s / m / h / d.
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from pathlib import Path

import yaml

RULES_DIR = Path(__file__).parent / "rules"
LEVELS = ["informational", "low", "medium", "high", "critical"]
# Fields worth showing when an event is printed as evidence.
EVIDENCE_FIELDS = ["user", "ip", "country", "order_id", "order_owner", "amount",
                   "new_iban", "reason", "path"]


# ---------------------------------------------------------------- loading ---

def load_events(lines) -> list[dict]:
    """Keep only our JSON security events. Uvicorn access lines etc. are skipped."""
    events = []
    for line in lines:
        line = line.strip()
        if not line.startswith("{"):
            continue
        try:
            ev = json.loads(line)
        except json.JSONDecodeError:
            continue
        if "event" not in ev or "ts" not in ev:
            continue
        ev["_ts"] = datetime.fromisoformat(ev["ts"])
        events.append(ev)
    events.sort(key=lambda e: e["_ts"])
    return events


def enrich(events: list[dict]) -> None:
    """Pipeline enrichment, the job a SIEM ingest pipeline would do.

    country_first_seen: on login_success, True if this user has logged in
    before but never from this country. The first login only sets a baseline.
    """
    seen: dict[str, set] = defaultdict(set)
    for ev in events:
        if ev["event"] != "login_success":
            continue
        countries = seen[ev.get("user")]
        ev["country_first_seen"] = bool(countries) and ev.get("country") not in countries
        countries.add(ev.get("country"))


# ------------------------------------------------------ condition parsing ---

_TOKEN = re.compile(r"\s*(\(|\)|[A-Za-z_][A-Za-z0-9_]*)")


def parse_condition(text: str, names: set[str]):
    """Parse e.g. 'selection and not (a or b)' into a nested tuple tree."""
    tokens, pos, text = [], 0, text.strip()
    while pos < len(text):
        m = _TOKEN.match(text, pos)
        if not m:
            raise ValueError(f"unsupported condition syntax: {text!r}")
        tokens.append(m.group(1))
        pos = m.end()

    def expr(i):  # expr := term ('or' term)*
        node, i = term(i)
        while i < len(tokens) and tokens[i] == "or":
            rhs, i = term(i + 1)
            node = ("or", node, rhs)
        return node, i

    def term(i):  # term := factor ('and' factor)*
        node, i = factor(i)
        while i < len(tokens) and tokens[i] == "and":
            rhs, i = factor(i + 1)
            node = ("and", node, rhs)
        return node, i

    def factor(i):  # factor := 'not' factor | '(' expr ')' | name
        if i >= len(tokens):
            raise ValueError(f"condition ends early: {text!r}")
        tok = tokens[i]
        if tok == "not":
            node, i = factor(i + 1)
            return ("not", node), i
        if tok == "(":
            node, i = expr(i + 1)
            if i >= len(tokens) or tokens[i] != ")":
                raise ValueError(f"missing ')' in condition: {text!r}")
            return node, i + 1
        if tok not in names:
            raise ValueError(f"condition uses unknown selection {tok!r}: {text!r}")
        return ("ref", tok), i + 1

    tree, end = expr(0)
    if end != len(tokens):
        raise ValueError(f"unexpected {tokens[end]!r} in condition: {text!r}")
    return tree


def eval_condition(tree, results: dict[str, bool]) -> bool:
    op = tree[0]
    if op == "ref":
        return results[tree[1]]
    if op == "not":
        return not eval_condition(tree[1], results)
    if op == "and":
        return eval_condition(tree[1], results) and eval_condition(tree[2], results)
    return eval_condition(tree[1], results) or eval_condition(tree[2], results)


# ---------------------------------------------------------------- matching ---

_MODIFIERS = {"contains", "startswith", "endswith", "re", "gt", "gte", "lt", "lte",
              "fieldref", "all"}


def match_value(actual, expected, mods: list[str], event: dict) -> bool:
    if "fieldref" in mods:
        if expected not in event:
            return False
        expected = event[expected]
    if expected is None:  # Sigma `null`: the field must be absent / null
        return actual is None
    if actual is None:
        return False
    if "re" in mods:
        return re.search(str(expected), str(actual)) is not None
    for op in ("gt", "gte", "lt", "lte"):
        if op in mods:
            a, e = float(actual), float(expected)
            return {"gt": a > e, "gte": a >= e, "lt": a < e, "lte": a <= e}[op]
    # Sigma string matching is case-insensitive.
    a, e = str(actual).lower(), str(expected).lower()
    if "contains" in mods:
        return e in a
    if "startswith" in mods:
        return a.startswith(e)
    if "endswith" in mods:
        return a.endswith(e)
    return a == e


def match_selection(selection, event: dict) -> bool:
    if isinstance(selection, list):  # list of maps = OR
        return any(match_selection(s, event) for s in selection)
    for key, expected in selection.items():  # map = AND of fields
        fieldname, *mods = key.split("|")
        unknown = set(mods) - _MODIFIERS
        if unknown:
            raise ValueError(f"unsupported modifier(s) {unknown} in {key!r}")
        values = expected if isinstance(expected, list) else [expected]
        combine = all if "all" in mods else any
        if not combine(match_value(event.get(fieldname), v, mods, event) for v in values):
            return False
    return True


# ------------------------------------------------------------------- rules ---

@dataclass
class Rule:
    doc: dict
    file: str
    condition: tuple | None = None

    @property
    def title(self): return self.doc["title"]
    @property
    def level(self): return self.doc.get("level", "medium")
    @property
    def tags(self): return [t for t in self.doc.get("tags", []) if re.match(r"attack\.t\d", t)]

    def matches(self, event: dict) -> bool:
        det = self.doc["detection"]
        results = {name: match_selection(sel, event)
                   for name, sel in det.items() if name != "condition"}
        return eval_condition(self.condition, results)


@dataclass
class Alert:
    rule: Rule
    events: list[dict]
    group: dict = field(default_factory=dict)
    value: int | None = None  # the counted number for count correlations

    def to_dict(self) -> dict:
        return {
            "rule": self.rule.title, "id": self.rule.doc["id"], "level": self.rule.level,
            "attack": self.rule.tags, "group": self.group, "value": self.value,
            "first": self.events[0]["ts"], "last": self.events[-1]["ts"],
            "events": [{k: v for k, v in e.items() if not k.startswith("_")} for e in self.events],
        }


def load_rules(rules_dir: Path) -> tuple[list[Rule], list[Rule], dict[str, Rule]]:
    detections, correlations, by_ref = [], [], {}
    for path in sorted(rules_dir.glob("*.yml")):
        for doc in yaml.safe_load_all(path.read_text()):
            if not doc:
                continue
            rule = Rule(doc, path.name)
            if "correlation" in doc:
                correlations.append(rule)
            elif "detection" in doc:
                det = doc["detection"]
                names = {k for k in det if k != "condition"}
                rule.condition = parse_condition(det["condition"], names)
                detections.append(rule)
                for ref in (doc.get("name"), doc["id"]):
                    if ref:
                        if ref in by_ref:
                            raise ValueError(f"duplicate rule name/id {ref!r} in {path.name}")
                        by_ref[ref] = rule
            else:
                raise ValueError(f"{path.name}: {doc.get('title')!r} has no detection or correlation")
    for corr in correlations:
        for ref in corr.doc["correlation"]["rules"]:
            if ref not in by_ref:
                raise ValueError(f"{corr.file}: correlation references unknown rule {ref!r}")
    return detections, correlations, by_ref


# ------------------------------------------------------------- correlation ---

def parse_timespan(text: str) -> timedelta:
    m = re.fullmatch(r"(\d+)([smhd])", str(text))
    if not m:
        raise ValueError(f"unsupported timespan {text!r}")
    unit = {"s": "seconds", "m": "minutes", "h": "hours", "d": "days"}[m.group(2)]
    return timedelta(**{unit: int(m.group(1))})


def group_events(events, group_by):
    groups = defaultdict(list)
    for ev in events:
        if all(ev.get(f) is not None for f in group_by):
            groups[tuple(ev[f] for f in group_by)].append(ev)
    return groups


def run_count(corr: Rule, events: list[dict]):
    """event_count / value_count over a sliding window, one alert per burst."""
    spec = corr.doc["correlation"]
    span = parse_timespan(spec["timespan"])
    group_by = spec.get("group-by", [])
    cond = dict(spec["condition"])
    count_field = cond.pop("field", None)
    if set(cond) - {"gt", "gte"}:
        raise ValueError(f"{corr.file}: only gt/gte count conditions are supported")

    def value(window):
        if spec["type"] == "event_count":
            return len(window)
        return len({str(e[count_field]) for e in window if e.get(count_field) is not None})

    def met(n):
        return all(n > v if op == "gt" else n >= v for op, v in cond.items())

    for key, evs in group_events(events, group_by).items():
        start = end = 0
        while end < len(evs):
            while evs[end]["_ts"] - evs[start]["_ts"] > span:
                start += 1
            if met(value(evs[start:end + 1])):
                # Extend over the rest of the burst so the alert reports its full size.
                while end + 1 < len(evs) and evs[end + 1]["_ts"] - evs[start]["_ts"] <= span:
                    end += 1
                window = evs[start:end + 1]
                yield Alert(corr, window, dict(zip(group_by, key)), value(window))
                start = end + 1  # never reuse these events in another alert
            end += 1


def run_temporal(corr: Rule, events: list[dict], by_ref: dict[str, Rule]):
    """temporal: all referenced rules hit within timespan, any order.
    temporal_ordered: same, but in the order listed."""
    spec = corr.doc["correlation"]
    span = parse_timespan(spec["timespan"])
    group_by = spec.get("group-by", [])
    refs = spec["rules"]
    ordered = spec["type"] == "temporal_ordered"

    tagged = []  # (event, set of referenced-rule indexes it matches)
    for ev in events:
        hits = {i for i, ref in enumerate(refs) if by_ref[ref].matches(ev)}
        if hits:
            ev["_hits"] = hits
            tagged.append(ev)

    for key, evs in group_events(tagged, group_by).items():
        i = 0
        while i < len(evs):
            first = evs[i]
            if ordered and 0 not in first["_hits"]:
                i += 1
                continue
            chain, need = [], 0
            covered = set()
            for j in range(i, len(evs)):
                ev = evs[j]
                if ev["_ts"] - first["_ts"] > span:
                    break
                if ordered:
                    if need in ev["_hits"]:
                        chain.append(ev)
                        need += 1
                elif ev["_hits"] - covered:
                    chain.append(ev)
                    covered |= ev["_hits"]
                if (need if ordered else len(covered)) == len(refs):
                    yield Alert(corr, chain, dict(zip(group_by, key)))
                    i = j  # continue after the completed chain
                    break
            i += 1


# -------------------------------------------------------------------- main ---

def detect(events: list[dict], rules_dir: Path = RULES_DIR):
    enrich(events)
    detections, correlations, by_ref = load_rules(rules_dir)
    alerts: list[Alert] = []

    # Base rules referenced by a correlation are building blocks: they don't
    # alert on their own unless that correlation sets `generate: true`.
    building_blocks = {id(by_ref[ref]) for c in correlations
                       if not c.doc.get("generate", False)
                       for ref in c.doc["correlation"]["rules"]}
    for rule in detections:
        if id(rule) in building_blocks:
            continue
        alerts += [Alert(rule, [ev]) for ev in events if rule.matches(ev)]

    for corr in correlations:
        kind = corr.doc["correlation"]["type"]
        if kind in ("event_count", "value_count"):
            refs = [by_ref[r] for r in corr.doc["correlation"]["rules"]]
            alerts += run_count(corr, [ev for ev in events if any(r.matches(ev) for r in refs)])
        elif kind in ("temporal", "temporal_ordered"):
            alerts += run_temporal(corr, events, by_ref)
        else:
            raise ValueError(f"{corr.file}: unsupported correlation type {kind!r}")

    alerts.sort(key=lambda a: a.events[0]["_ts"])
    return alerts, detections, correlations


def describe(ev: dict) -> str:
    parts = [f"{k}={ev[k]}" for k in EVIDENCE_FIELDS if ev.get(k) is not None]
    return f"{ev['_ts']:%H:%M:%S.%f}"[:-3] + f"  {ev['event']:<18} " + " ".join(parts)


def print_alerts(alerts: list[Alert], rules: list[Rule], n_events: int) -> None:
    for a in alerts:
        span = (a.events[-1]["_ts"] - a.events[0]["_ts"]).total_seconds()
        print(f"[{a.rule.level.upper()}] {a.rule.title}")
        print(f"    ATT&CK: {', '.join(a.rule.tags) or '-'}    rule: {a.rule.file}")
        meta = [f"{k}={v}" for k, v in a.group.items()]
        if a.value is not None:
            meta.append(f"count={a.value}")
        meta.append(f"events={len(a.events)} over {span:.2f}s")
        print("    " + "  ".join(meta))
        shown = a.events if len(a.events) <= 6 else a.events[:3] + [None] + a.events[-2:]
        for ev in shown:
            print("      ..." if ev is None else "      " + describe(ev))
        print()

    counts = defaultdict(int)
    for a in alerts:
        counts[a.rule.title] += 1
    print(f"Summary: {len(alerts)} alert(s) from {n_events} events")
    for r in rules:
        print(f"  {counts[r.title]:>3}  [{r.level}] {r.title}")


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("logfile", help="JSON-lines log file, or - for stdin")
    ap.add_argument("--rules", type=Path, default=RULES_DIR)
    ap.add_argument("--json", action="store_true", help="print alerts as JSON lines")
    args = ap.parse_args()

    stream = sys.stdin if args.logfile == "-" else open(args.logfile, encoding="utf-8")
    with stream:
        events = load_events(stream)
    alerts, detections, correlations = detect(events, args.rules)

    if args.json:
        for a in alerts:
            print(json.dumps(a.to_dict(), default=str))
    else:
        # List the rules that can alert (not the building blocks).
        blocks = {r for c in correlations for r in c.doc["correlation"]["rules"]}
        alerting = [r for r in detections
                    if r.doc.get("name") not in blocks and r.doc["id"] not in blocks]
        print_alerts(alerts, alerting + correlations, len(events))
    return 0


if __name__ == "__main__":
    sys.exit(main())
