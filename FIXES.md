# Fixes

Each bug from the `vulnerable` branch, how `main` fixes it, and how to check.
On `vulnerable` every exploit prints `[!] EXPLOITED`; on `main` they print
`[-] Not exploited`. `git diff vulnerable..main` shows exactly what changed.

The schema fixes only apply to a new database, so reset it first:

```bash
docker compose down -v && docker compose up --build
```

## 1. Race condition on `POST /withdraw`

**Was:** read the balance, check it, wait for the simulated bank call, then
write back a value based on the old read. 20 parallel full-balance withdrawals
all passed the check, so the account paid out 20x.

**Fix:**
- One atomic statement does the check and the debit, so there's no gap to race:
  ```sql
  UPDATE accounts SET balance = balance - %s
  WHERE user_id = %s AND balance >= %s RETURNING balance;
  ```
  A request that loses gets no row back and is rejected.
- `CHECK (balance >= 0)` on `accounts` as a database backstop.
- Optional `Idempotency-Key` header with a unique index on
  `(user_id, idempotency_key)`, so a retried request is charged once.

**Check:** `python race_withdraw.py` accepts 1 of 20 and the balance never goes
negative. Two withdrawals with the same key: the second returns
`duplicate_ignored`.

## 2. IDOR on `GET /orders/{order_id}`

**Was:** orders were fetched by id alone, so changing the number in the URL
showed other customers' trades (a KVKK breach).

**Fix:** the query is scoped to the caller with `WHERE id = %s AND user_id = %s`.
Someone else's order returns a plain 404, without confirming it exists.

**Check:** `python idor_orders.py` leaks 0 orders.

## 3. Negative quantity on `POST /orders`

**Was:** a buy of `-10` made the total negative, so the balance went up.

**Fix:** `quantity: Annotated[Decimal, Field(gt=0)]` rejects it with a 422
before any logic runs, and `CHECK (quantity > 0)` on `orders` backs it up. Buys
also lock the account row (`SELECT ... FOR UPDATE`).

**Check:** `python negative_quantity.py` gets a 422 and the balance is unchanged.

## 4. No rate limiting on `POST /login`

**Was:** no throttle or lockout, so a password list could be tried at full speed.

**Fix:** slowapi limits `/login` to 5 per minute per IP (`/register` to 10).
Going over returns 429 and logs `rate_limited`.

The limiter keys on `client_ip()` (next section), not slowapi's default
`get_remote_address`. Behind a load balancer the default sees the proxy's IP, so
all users would share one limit and anyone could lock everyone out. Limits are
kept in memory, so they're only exact with one instance. More instances would
need a shared store like Redis.

**Check:** `python credential_stuffing.py` hits 429 after a few tries and never
finds the password.

## Follow-up: spoofable client IP (`X-Forwarded-For`)

**Was:** logs used the first `X-Forwarded-For` entry, which the client writes.
`curl -H "X-Forwarded-For: 1.2.3.4"` picked the IP in every security event, so
IP-based detections could be dodged or pointed at someone else.

**Fix:** each proxy appends one entry on the right, so only those are trusted.
With `TRUSTED_PROXY_HOPS=N`, the client is the Nth entry from the right. The
default `0` (local, no proxy) ignores the header and uses the TCP peer, since
trusting it there would also let anyone dodge the rate limit. Set `N` for each
deployment and confirm it with a real request.

**Check:** once the limit is hit, rotating `X-Forwarded-For` still returns 429
and the logged `ip` doesn't change. With `TRUSTED_PROXY_HOPS=1`,
`"6.6.6.6, 203.0.113.7"` resolves to `203.0.113.7`.

## Hardening found by the threat model

These weren't planted bugs. They came up while writing `THREAT_MODEL.md`.

**Weak JWT secret.** `auth.py` fell back to `"dev-only"` when `JWT_SECRET` was
missing, so a deploy that forgot it signed tokens with a key printed in this
repo. Now the app refuses to start unless the secret is at least 32 characters
and isn't a known placeholder. Compose also stops if it's missing from `.env`.

**App connected as a database superuser.** Any bug or SQL injection had full
control of Postgres, including running programs on the server with
`COPY ... PROGRAM`. `db/app_role.sh` creates `miniapp_app` with only what the
code uses: it can update an IBAN, a balance or a holding, and only append to
orders and withdrawals. Its password comes from `APP_DB_PASSWORD` in `.env`,
and the superuser password moved from `docker-compose.yml` to `POSTGRES_PASSWORD`.

**Full IBANs in logs.** IBANs are personal data under KVKK, and logs travel
further than the database. `security_event()` now masks any field with `iban`
in its name to `TR********************0001`. The full IBAN stays in the
`withdrawals` table.

**Check:** with an empty or placeholder secret the app exits with
`RuntimeError: JWT_SECRET must be set...`. As `miniapp_app`, `UPDATE`,
`DELETE`, `DROP`, `CREATE TABLE` and `COPY ... PROGRAM` are all refused.
`grep -cE 'TR[0-9]{24}' detections/samples/main.jsonl` returns 0.

The secret check and the new role need a filled-in `.env` (see `.env.example`),
and the role needs a fresh database.
