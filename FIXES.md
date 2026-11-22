# Fixes

Each vulnerability from the `vulnerable` branch, the fix applied on `main`, and
how to prove it. You may run the exploit scripts against both branches:

```bash
# on `vulnerable`  -> every script prints [!] EXPLOITED
# on `main`        -> every script prints [-] Not exploited
git diff vulnerable..main        # see exactly what changed
```

---

## Vulnerability 1 — Race condition on `POST /withdraw`

**Was:** read balance → check → sleep (simulated bank call) → write back a value
computed from the stale read. 20 concurrent full-balance withdrawals all passed
the check before any write, so the account paid out 20×.

**Fix:**
- Single atomic conditional decrement — the debit and the check are one
  statement, so there is no check-then-act window:
  ```sql
  UPDATE accounts SET balance = balance - %s
  WHERE user_id = %s AND balance >= %s RETURNING balance;
  ```
  Requests that lose the race get no row back and are rejected.
- `CHECK (balance >= 0)` on `accounts` as a database-level backstop.
- Optional `Idempotency-Key` header + partial `UNIQUE` index on
  `(user_id, idempotency_key)`, so a retried/double-submitted request is a no-op.

**Proof:** `python race_withdraw.py` → 1/20 accepted, balance 0, never negative.
Idempotency: two withdrawals with the same key → second returns
`duplicate_ignored`, charged once.

## Vulnerability 2 — IDOR on `GET /orders/{order_id}`

**Was:** order fetched by id only; any user could read any order by changing the
number in the URL (a KVKK personal-data breach).

**Fix:** scope the query to the caller — `WHERE id = %s AND user_id = %s`. Another
user's id returns a plain 404; we don't confirm the order even exists.

**Proof:** `python idor_orders.py` → 0 other users' orders leaked.

## Vulnerability 3 — Negative quantity on `POST /orders`

**Was:** `quantity` unconstrained; a `buy` of `-10` made `total` negative, so the
balance check passed and the balance *increased*.

**Fix:** reject at the edge with `quantity: Annotated[Decimal, Field(gt=0)]`
(422 before any logic), plus `CHECK (quantity > 0)` on the `orders` table. Buy
orders also take a row lock (`SELECT ... FOR UPDATE`) to stay consistent under
concurrency.

**Proof:** `python negative_quantity.py` → 422, balance unchanged.

## Vulnerability 4 — No rate limiting on `POST /login`

**Was:** no throttle, lockout or CAPTCHA; a wordlist could be walked at full
speed, from any number of fake countries.

**Fix:** `slowapi` per-IP limit — `@limiter.limit("5/minute")` on `/login`
(and `10/minute` on `/register`). Exceeding it returns 429 and logs a
`rate_limited` event.

**Proof:** `python credential_stuffing.py` → 429 after a few tries, password
never recovered.

---

## Note on the schema

The fixes to `db/init.sql` (the `CHECK` constraints and the idempotency index)
only apply to a new database. Recreate the volume before testing the fixes:

```bash
docker compose down -v && docker compose up --build
```
