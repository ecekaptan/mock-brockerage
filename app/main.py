"""a mock brokerage API — FIXED version.

Companion to the `vulnerable` branch. Each fix is marked "FIX" and maps to the
bug it closes. Run the exploit scripts against this version: they should all
report "[-] Not exploited".

  1. Race condition on POST /withdraw  -> atomic conditional UPDATE + idempotency key
  2. IDOR on GET /orders/{order_id}     -> ownership check in the query
  3. Business logic on POST /orders     -> quantity must be > 0 (validated)
  4. No rate limiting on POST /login    -> per-IP limit via slowapi
"""
from contextlib import asynccontextmanager
from decimal import Decimal
from typing import Annotated, Literal, Optional

from fastapi import Depends, FastAPI, Header, HTTPException, Request
from pydantic import BaseModel, Field
from slowapi import Limiter
from slowapi.errors import RateLimitExceeded
from slowapi.util import get_remote_address

from .auth import create_token, current_user, hash_password, verify_password
from .db import pool
from .logs import security_event

# mock prices in turkish liras
prices = {
    "THYAO": Decimal("310.50"),
    "BIMAS": Decimal("525.00"),
    "FROTO": Decimal("1050.00"),
    "ASELS": Decimal("142.30"),
    "TCELL": Decimal("98.75"),
}

starting_balance = Decimal("1000.00")
demo_users = [("ali", "Password123!", "TR000000000000000000000001"),
              ("veli", "Password123!", "TR000000000000000000000002")]

limiter = Limiter(key_func=get_remote_address)


def seed_demo_users() -> None:
    with pool.connection() as conn:
        for username, password, iban in demo_users:
            row = conn.execute("SELECT id FROM users WHERE username = %s", (username,)).fetchone()
            if row:
                continue
            with conn.transaction():
                user = conn.execute(
                    "INSERT INTO users (username, password_hash, iban) VALUES (%s, %s, %s) RETURNING id",
                    (username, hash_password(password), iban),
                ).fetchone()
                conn.execute(
                    "INSERT INTO accounts (user_id, balance) VALUES (%s, %s)",
                    (user["id"], starting_balance),
                )
                conn.execute(
                    "INSERT INTO orders (user_id, symbol, side, quantity, price, total) "
                    "VALUES (%s, 'THYAO', 'buy', 1, 310.50, 310.50)",
                    (user["id"],),
                )


@asynccontextmanager
async def lifespan(app: FastAPI):
    pool.open(wait=True)
    seed_demo_users()
    yield
    pool.close()


app = FastAPI(title="MiniApp (fixed)", lifespan=lifespan)
app.state.limiter = limiter


@app.exception_handler(RateLimitExceeded)
def _rate_limit_handler(request: Request, exc: RateLimitExceeded):
    # fix (vulnerability 4): refuse and log instead of answering unlimited guesses.
    security_event("rate_limited", path=request.url.path, **client_ctx(request))
    raise HTTPException(status_code=429, detail="Too many requests")


def client_ctx(request: Request) -> dict:
    forwarded = request.headers.get("x-forwarded-for")
    ip = forwarded.split(",")[0].strip() if forwarded else (request.client.host if request.client else None)
    return {
        "ip": ip,
        "country": request.headers.get("x-client-country", "TR"),
        "user_agent": request.headers.get("user-agent"),
    }


# ---------- Schemas ----------

class Credentials(BaseModel):
    username: str
    password: str


class OrderIn(BaseModel):
    symbol: str
    side: Literal["buy", "sell"]
    # fix (vulnerability 3): quantity must be strictly positive. A negative or zero
    # quantity is rejected at the edge with a 422 before any logic runs.
    quantity: Annotated[Decimal, Field(gt=0)]


class WithdrawIn(BaseModel):
    amount: Annotated[Decimal, Field(gt=0)]


class IbanIn(BaseModel):
    iban: str


# ---------- Endpoints ----------

@app.get("/health")
def health():
    return {"status": "ok"}


@app.post("/register", status_code=201)
@limiter.limit("10/minute")
def register(body: Credentials, request: Request):
    with pool.connection() as conn:
        if conn.execute("SELECT 1 FROM users WHERE username = %s", (body.username,)).fetchone():
            raise HTTPException(status_code=409, detail="Username taken")
        with conn.transaction():
            user = conn.execute(
                "INSERT INTO users (username, password_hash) VALUES (%s, %s) RETURNING id",
                (body.username, hash_password(body.password)),
            ).fetchone()
            conn.execute(
                "INSERT INTO accounts (user_id, balance) VALUES (%s, %s)",
                (user["id"], starting_balance),
            )
    security_event("user_registered", user=body.username, **client_ctx(request))
    return {"id": user["id"], "username": body.username}


@app.post("/login")
@limiter.limit("5/minute")
def login(body: Credentials, request: Request):
    # fix (vulnerability 4): slowapi caps attempts per IP. Brute force / credential
    # stuffing now hits 429 long before it can walk a wordlist.
    ctx = client_ctx(request)
    with pool.connection() as conn:
        user = conn.execute(
            "SELECT id, username, password_hash FROM users WHERE username = %s", (body.username,)
        ).fetchone()
    if not user or not verify_password(body.password, user["password_hash"]):
        security_event("login_failed", user=body.username, **ctx)
        raise HTTPException(status_code=401, detail="Invalid credentials")
    security_event("login_success", user=user["username"], **ctx)
    return {"access_token": create_token(user["id"], user["username"]), "token_type": "bearer"}


@app.get("/me")
def me(user: dict = Depends(current_user)):
    with pool.connection() as conn:
        row = conn.execute(
            "SELECT u.id, u.username, u.iban, a.balance FROM users u "
            "JOIN accounts a ON a.user_id = u.id WHERE u.id = %s",
            (user["id"],),
        ).fetchone()
        holdings = conn.execute(
            "SELECT symbol, quantity FROM holdings WHERE user_id = %s AND quantity <> 0",
            (user["id"],),
        ).fetchall()
    return {**row, "holdings": holdings}


@app.put("/me/iban")
def change_iban(body: IbanIn, request: Request, user: dict = Depends(current_user)):
    with pool.connection() as conn:
        old = conn.execute("SELECT iban FROM users WHERE id = %s", (user["id"],)).fetchone()
        conn.execute("UPDATE users SET iban = %s WHERE id = %s", (body.iban, user["id"]))
    security_event("iban_changed", user=user["username"], old_iban=old["iban"],
                   new_iban=body.iban, **client_ctx(request))
    return {"iban": body.iban}


@app.get("/prices")
def get_prices():
    return prices


@app.post("/orders", status_code=201)
def place_order(body: OrderIn, request: Request, user: dict = Depends(current_user)):
    symbol = body.symbol.upper()
    if symbol not in prices:
        raise HTTPException(status_code=400, detail="Unknown symbol")
    price = prices[symbol]
    # quantity is guaranteed > 0 by the schema, so total is always positive.
    total = (body.quantity * price).quantize(Decimal("0.01"))

    with pool.connection() as conn, conn.transaction():
        balance = conn.execute(
            "SELECT balance FROM accounts WHERE user_id = %s FOR UPDATE", (user["id"],)
        ).fetchone()["balance"]
        held = conn.execute(
            "SELECT quantity FROM holdings WHERE user_id = %s AND symbol = %s", (user["id"], symbol)
        ).fetchone()
        held_qty = held["quantity"] if held else Decimal("0")

        if body.side == "buy":
            if balance < total:
                raise HTTPException(status_code=400, detail="Insufficient balance")
            balance_delta, qty_delta = -total, body.quantity
        else:
            if held_qty < body.quantity:
                raise HTTPException(status_code=400, detail="Insufficient holdings")
            balance_delta, qty_delta = total, -body.quantity

        conn.execute(
            "UPDATE accounts SET balance = balance + %s WHERE user_id = %s", (balance_delta, user["id"])
        )
        conn.execute(
            "INSERT INTO holdings (user_id, symbol, quantity) VALUES (%s, %s, %s) "
            "ON CONFLICT (user_id, symbol) DO UPDATE SET quantity = holdings.quantity + EXCLUDED.quantity",
            (user["id"], symbol, qty_delta),
        )
        order = conn.execute(
            "INSERT INTO orders (user_id, symbol, side, quantity, price, total) "
            "VALUES (%s, %s, %s, %s, %s, %s) RETURNING *",
            (user["id"], symbol, body.side, body.quantity, price, total),
        ).fetchone()

    security_event("order_placed", user=user["username"], order_id=order["id"], symbol=symbol,
                   side=body.side, quantity=body.quantity, total=total, **client_ctx(request))
    return order


@app.get("/orders")
def my_orders(user: dict = Depends(current_user)):
    with pool.connection() as conn:
        return conn.execute(
            "SELECT * FROM orders WHERE user_id = %s ORDER BY id DESC", (user["id"],)
        ).fetchall()


@app.get("/orders/{order_id}")
def get_order(order_id: int, request: Request, user: dict = Depends(current_user)):
    with pool.connection() as conn:
        # fix (vulnerability 2): scope the lookup to the caller. Another user's id simply
        # returns 404 — we don't even confirm the order exists.
        order = conn.execute(
            "SELECT * FROM orders WHERE id = %s AND user_id = %s", (order_id, user["id"])
        ).fetchone()
        if not order:
            raise HTTPException(status_code=404, detail="Order not found")
    security_event("order_read", user=user["username"], order_id=order_id, **client_ctx(request))
    return order


@app.post("/withdraw")
def withdraw(
    body: WithdrawIn,
    request: Request,
    user: dict = Depends(current_user),
    idempotency_key: Optional[str] = Header(default=None, alias="Idempotency-Key"),
):
    with pool.connection() as conn, conn.transaction():
        iban = conn.execute("SELECT iban FROM users WHERE id = %s", (user["id"],)).fetchone()["iban"]
        if not iban:
            raise HTTPException(status_code=400, detail="No IBAN on file")

        # fix (vulnerability 1): replay protection. A repeated key is a no-op, so a
        # double-submitted request never pays out twice.
        if idempotency_key:
            seen = conn.execute(
                "SELECT 1 FROM withdrawals WHERE user_id = %s AND idempotency_key = %s",
                (user["id"], idempotency_key),
            ).fetchone()
            if seen:
                bal = conn.execute(
                    "SELECT balance FROM accounts WHERE user_id = %s", (user["id"],)
                ).fetchone()["balance"]
                return {"status": "duplicate_ignored", "amount": body.amount, "balance": bal}

        # fix (vulnerability 1): single atomic conditional decrement. The row is debited
        # only if it still holds enough; concurrent requests that lose the race
        # get no row back and are rejected. No check-then-act window.
        row = conn.execute(
            "UPDATE accounts SET balance = balance - %s "
            "WHERE user_id = %s AND balance >= %s RETURNING balance",
            (body.amount, user["id"], body.amount),
        ).fetchone()
        if row is None:
            raise HTTPException(status_code=400, detail="Insufficient balance")

        conn.execute(
            "INSERT INTO withdrawals (user_id, amount, iban, idempotency_key) VALUES (%s, %s, %s, %s)",
            (user["id"], body.amount, iban, idempotency_key),
        )
        new_balance = row["balance"]

    security_event("withdraw", user=user["username"], amount=body.amount, iban=iban,
                   **client_ctx(request))
    return {"status": "sent", "amount": body.amount, "balance": new_balance}
