# Detections

Sigma rules for MiniApp's JSON security log, plus `detect.py`, a small engine that runs them locally. It is not a SIEM. In production the same rules would be converted with [sigma-cli](https://github.com/SigmaHQ/sigma-cli) for Elastic, Splunk or Wazuh. The rule list and ATT&CK mapping are in the main README.

## Run it

From the repo root, after `pip install -r requirements-dev.txt`:

```bash
python detections/detect.py detections/samples/main.jsonl         # fixed app
python detections/detect.py detections/samples/vulnerable.jsonl   # vulnerable branch
docker compose logs api --no-log-prefix | python detections/detect.py -   # live
cd detections && python -m unittest -v                            # tests
```

## Files

| Path | What |
|---|---|
| `rules/*.yml` | Sigma rules, using [correlation rules](https://github.com/SigmaHQ/sigma-specification) for counts and sequences |
| `detect.py` | Loads the rules, enriches events, matches, correlates, prints alerts |
| `scenarios.py` | Traffic the exploits don't create: account takeover, multi-account stuffing, and normal users who must not trigger alerts |
| `generate_sample.sh` | Runs scenarios and exploits against a live stack and saves the log |
| `samples/` | Logs captured from real runs against each branch |
| `test_detect.py` | Thresholds, near misses, expected alerts per sample |

## Notes

- Sigma has no "first time seen" check, so `detect.py` adds `country_first_seen` to logins before matching. A SIEM would do this with an Elastic new terms rule or a Splunk lookup. A user's first login sets the baseline and is never flagged.
- The IDOR rule can only fire on the vulnerable branch, because the fixed app never returns someone else's order. On `main` the enumeration rule catches the attempt instead.
- The fixed app logs `withdraw_rejected` and `order_read_denied` so blocked attacks still leave a trace. Without them the burst and enumeration rules couldn't fire on `main`.
- IP-based rules need a trustworthy IP, which is why the `X-Forwarded-For` fix in `FIXES.md` came first.
- There is no real load balancer locally. `scenarios.py` gives each actor an IP through `X-Forwarded-For`, which the fixed app only trusts because `generate_sample.sh` starts it with `TRUSTED_PROXY_HOPS=1`. `X-Client-Country` is also client-supplied here.
