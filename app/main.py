"""a deliberately vulnerable mock brokerage API.

FOR SECURITY TRAINING ONLY. Run locally with fake data.

Added vulnerabilities (search for "VULN"):
  1. Race condition on POST /withdraw   (check-then-act, no lock, no idempotency)
  2. IDOR on GET /orders/{order_id}     (no ownership check)
  3. Business logic on POST /orders     (negative quantity accepted)
  4. No rate limiting on POST /login    (credential stuffing / brute force)
"""
import time
from contextlib import asynccontextmanager
from decimal import Decimal
from typing import Literal

from fastapi import Depends, FastAPI, HTTPException, Request
from pydantic import BaseModel

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
                # Give each demo user one order so the IDOR has something to find.
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


app = FastAPI(title="MiniApp (vulnerable)", lifespan=lifespan)


def client_ctx(request: Request) -> dict:
    """Who is calling, for the logs.

    X-Client-Country simulates the geo header a load balancer adds in
    production (e.g. Google Cloud's X-Client-Geo-Location). Exploit scripts
    set it to fake logins from different countries.
    """
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
    # VULN 3: no constraint on quantity — zero and negative values are accepted.
    quantity: Decimal


class WithdrawIn(BaseModel):
    amount: Decimal


class IbanIn(BaseModel):
    iban: str


# ---------- Endpoints ----------

@app.get("/health")
def health():
    return {"status": "ok"}


@app.post("/register", status_code=201)
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
def login(body: Credentials, request: Request):
    # VULN 4: no rate limiting, no lockout, no CAPTCHA. Unlimited guesses per IP/user.
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
    # Not a planted bug, but note for the README: production should require
    # step-up auth (OTP) and a cooling-off period before a new IBAN can receive money.
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
    total = (body.quantity * price).quantize(Decimal("0.01"))

    with pool.connection() as conn, conn.transaction():
        balance = conn.execute(
            "SELECT balance FROM accounts WHERE user_id = %s", (user["id"],)
        ).fetchone()["balance"]
        held = conn.execute(
            "SELECT quantity FROM holdings WHERE user_id = %s AND symbol = %s", (user["id"], symbol)
        ).fetchone()
        held_qty = held["quantity"] if held else Decimal("0")

        if body.side == "buy":
            # VULN 3: with quantity < 0, total is negative, so this check always
            # passes and "balance - total" ADDS money to the account.
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
        # VULN 2: looks the order up by ID only. Any logged-in user can read
        # any other user's orders by changing the number in the URL.
        order = conn.execute("SELECT * FROM orders WHERE id = %s", (order_id,)).fetchone()
        if not order:
            raise HTTPException(status_code=404, detail="Order not found")
        owner = conn.execute("SELECT username FROM users WHERE id = %s", (order["user_id"],)).fetchone()
    security_event("order_read", user=user["username"], order_id=order_id,
                   order_owner=owner["username"], **client_ctx(request))
    return order


@app.post("/withdraw")
def withdraw(body: WithdrawIn, request: Request, user: dict = Depends(current_user)):
    if body.amount <= 0:
        raise HTTPException(status_code=400, detail="Amount must be positive")

    with pool.connection() as conn:
        # VULN 1: classic check-then-act race condition.
        # Step 1 reads the balance with no lock and no transaction...
        row = conn.execute(
            "SELECT a.balance, u.iban FROM accounts a JOIN users u ON u.id = a.user_id "
            "WHERE a.user_id = %s",
            (user["id"],),
        ).fetchone()
        if not row["iban"]:
            raise HTTPException(status_code=400, detail="No IBAN on file")
        if row["balance"] < body.amount:
            raise HTTPException(status_code=400, detail="Insufficient balance")

        # Step 2 simulates the call to the bank/payment provider (~200 ms).
        # Every concurrent request has already passed the check above.
        time.sleep(0.2)

        # Step 3 writes back a value computed from the stale read (lost update),
        # and records a payout for every request that got this far.
        new_balance = row["balance"] - body.amount
        conn.execute("UPDATE accounts SET balance = %s WHERE user_id = %s", (new_balance, user["id"]))
        conn.execute(
            "INSERT INTO withdrawals (user_id, amount, iban) VALUES (%s, %s, %s)",
            (user["id"], body.amount, row["iban"]),
        )

    security_event("withdraw", user=user["username"], amount=body.amount,
                   iban=row["iban"], **client_ctx(request))
    return {"status": "sent", "amount": body.amount, "balance": new_balance}
