# Security Assessment of a Mock Brokerage Platform

A small FastAPI + PostgreSQL trading API with four planted, fintech-specific vulnerabilities. The project shows the full loop: **build → attack → fix → deploy (GCP + Terraform) → detect (Sigma rules + local engine)**.

## Quick start

```bash
cp .env.example .env    # then fill in both values, e.g. with:
python3 -c 'import secrets; print(secrets.token_urlsafe(32))'
docker compose up --build
# API:  http://localhost:8000
```

Demo users (created on startup, 1,000 TRY each): `ali` / `Password123!` and `veli` / `Password123!`.

## Running the exploits

With the app running, open a second terminal at the repo root. Tooling has its own `requirements-dev.txt`, so the app image only ships what the app needs.

```bash
python3 -m venv .venv
source .venv/bin/activate          # needed again in each new terminal
pip install -r requirements-dev.txt

cd exploits
python race_withdraw.py            # vulnerability 1: drains 20x the balance
python idor_orders.py              # vulnerability 2: reads another user's orders
python negative_quantity.py        # vulnerability 3: mints money from a negative buy
python credential_stuffing.py      # vulnerability 4: brute forces login, unthrottled
```

Each script ends with `[!] EXPLOITED` or `[-] Not exploited`. Scripts target `http://localhost:8000` by default; override with `TARGET=...`.

## Endpoints

| Method | Path | Purpose |
|---|---|---|
| POST | `/register` | Create user (starts with 1,000 TRY) |
| POST | `/login` | Get a JWT |
| GET | `/me` | Balance, IBAN, holdings |
| PUT | `/me/iban` | Change payout IBAN |
| GET | `/prices` | Mock BIST prices |
| POST | `/orders` | Buy / sell `{symbol, side, quantity}` |
| GET | `/orders` | My orders |
| GET | `/orders/{id}` | One order |
| POST | `/withdraw` | Withdraw `{amount}` to IBAN |

## Added vulnerabilities

Search the code for `vulnerability`. Fixes are in `FIXES.md`.

| # | Bug | Where | Impact for a real brokerage |
|---|---|---|---|
| 1 | Race condition (check-then-act) | `POST /withdraw` | 20 concurrent full-balance withdrawals all succeed, 20x payout |
| 2 | IDOR | `GET /orders/{id}` | Any user reads any customer's trades (KVKK breach) |
| 3 | Negative quantity | `POST /orders` | Buying `-10` shares *adds* money to the account |
| 4 | No rate limiting | `POST /login` | Unlimited credential stuffing / brute force |

## Security logging

Security-relevant actions write one JSON line to stdout (`app/logs.py`): `login_success`, `login_failed`, `order_placed`, `order_read`, `withdraw`, `iban_changed`, `user_registered`. The fixed app also logs refused attempts: `withdraw_rejected`, `order_read_denied`, `rate_limited`. Fields include `user`, `ip`, `country`, `user_agent`. IBANs are masked to the country code and last 4 digits.

`X-Client-Country` stands in for the geo header a load balancer would add, so scripts can fake logins from other countries.

## Detections (MITRE ATT&CK)

Sigma rules live in `detections/rules/`. A small local engine runs them over the log:

```bash
python detections/detect.py detections/samples/main.jsonl
```

In production these rules would be converted with sigma-cli and run in a SIEM (Elastic, Splunk, Wazuh). This repo shows and tests the detection logic only; it doesn't host a SIEM.

| Detection | Signal | Technique |
|---|---|---|
| Credential stuffing | 3+ accounts failing login from one IP in 5 min | T1110.004 Credential Stuffing |
| Password guessing | 5+ failed logins, one IP, one account, 5 min | T1110.001 Password Guessing |
| Login rate limit hit | `rate_limited` on `/login` | T1110 Brute Force |
| Account takeover chain | login from a new country, then IBAN change, then withdrawal, within 15 min | T1078 Valid Accounts, T1098 Account Manipulation, T1657 Financial Theft |
| Withdrawal burst | 5+ withdrawal attempts by one user in 1 s (vulnerability 1) | T1190 Exploit Public-Facing App, T1657 |
| IDOR order read | `order_read` where caller isn't the owner (vulnerability 2, vulnerable branch only) | T1190, T1213 Data from Information Repositories |
| Order ID enumeration | 10+ refused order reads by one user in 1 min | T1190, T1213 |

ATT&CK fits application-logic abuse only loosely. More detail in `detections/README.md`.

## Roadmap

- [x] Vulnerable API, schema, Docker Compose, structured logs
- [x] `exploits/`: Python PoC for each bug
- [x] Fixes: atomic withdraw, `CHECK` constraints, idempotency keys, ownership checks, `quantity > 0`, rate limiting (see `FIXES.md`)
- [x] Re-run PoCs against the fixed version (all report "not exploited")
- [x] Container hardening: non-root user, pinned image, healthcheck, cap_drop, read-only fs, no-new-privileges, db not exposed
- [x] CI security gate: Semgrep, Gitleaks, Trivy, Checkov
- [x] Detections: Sigma rules mapped to ATT&CK, local engine, sample logs from both branches, tests
- [x] Threat model (STRIDE): `THREAT_MODEL.md`
- [ ] Findings write-up
