# Security Assessment of a Mock Brokerage Platform

A small FastAPI + PostgreSQL trading API with four planted, fintech-specific vulnerabilities. The project shows the full loop: **build → attack → fix → deploy (GCP + Terraform) → detect (Log Analytics + Sigma)**.

## Quick start

```bash
docker compose up --build
# API:  http://localhost:8000 
```

Demo users (created on startup, 1,000 TRY each): `ali` / `Password123!` and `veli` / `Password123!`.

## Running the exploits

With the app running, from a second terminal. macOS ships an externally-managed
Python (PEP 668), so use a virtual environment:

```bash
cd exploits
python3 -m venv .venv
source .venv/bin/activate          
pip install -r requirements.txt

python race_withdraw.py            # vulnerability 1 — drains 20x the balance
python idor_orders.py              # vulnerability 2 — reads another user's orders
python negative_quantity.py        # vulnerability 3 — mints money from a negative buy
python credential_stuffing.py      # vulnerability 4 — brute forces login, unthrottled
```

Each script prints a before/after and ends with `[!] EXPLOITED` or `[-] Not
exploited`, so re-running after the fixes is the proof they worked. Scripts
default to `http://localhost:8000`; override with `TARGET=...`.

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

Search the code for `vulnerability`.

| # | Bug | Where | Impact for a real brokerage |
|---|---|---|---|
| 1 | Race condition (check-then-act, lost update) | `POST /withdraw` | 20 concurrent withdrawals of the full balance all succeed → 20× payout |
| 2 | IDOR | `GET /orders/{id}` | Any user reads any customer's trades (KVKK breach) |
| 3 | Business logic: negative quantity | `POST /orders` | Buying `-10` shares *adds* money to the account |
| 4 | No rate limiting | `POST /login` | Unlimited credential stuffing / brute force |

## Security logging

Every security-relevant action writes one JSON line to stdout (`app/logs.py`): `login_success`, `login_failed`, `order_placed`, `order_read` (includes `order_owner`), `withdraw`, `iban_changed`, `user_registered`. Fields include `user`, `ip`, `country`, `user_agent`.

`X-Client-Country` simulates the geo header a cloud load balancer adds, so test scripts can fake logins from other countries.

## Roadmap

- [x] Vulnerable API, schema, Docker Compose, structured logs
- [x] `exploits/` — Python PoC for each bug (race condition first)
- [x] Fixes: atomic `UPDATE ... WHERE balance >= amount` / `SELECT ... FOR UPDATE`, `CHECK (balance >= 0)`, idempotency keys (unique index), ownership checks, `quantity > 0` validation, rate limiting (see `FIXES.md`)
- [x] Re-run PoCs against the fixed version (all report "not exploited")
- [ ] Dockerfile hardening (non-root, pinned image)
- [ ] Terraform: Cloud Run + Cloud SQL + Secret Manager + least-privilege service account
- [ ] CI security gate: Semgrep, Gitleaks, Trivy, Checkov
- [ ] Detections in GCP Log Analytics (MITRE ATT&CK) + alerting in Terraform + Sigma rules
- [ ] Threat model (STRIDE), findings write-up, demo video
