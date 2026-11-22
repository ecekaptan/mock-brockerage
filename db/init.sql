-- schema (fixed version)

CREATE TABLE users (
    id            SERIAL PRIMARY KEY,
    username      TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    iban          TEXT,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- fix (vulnerability 1): CHECK constraint is a last line of defense. Even if application
-- logic is bypassed, the database refuses to let a balance go negative.
CREATE TABLE accounts (
    user_id  INTEGER PRIMARY KEY REFERENCES users(id),
    balance  NUMERIC(18, 2) NOT NULL DEFAULT 0 CHECK (balance >= 0)
);

CREATE TABLE holdings (
    user_id  INTEGER NOT NULL REFERENCES users(id),
    symbol   TEXT NOT NULL,
    quantity NUMERIC(18, 4) NOT NULL DEFAULT 0,
    PRIMARY KEY (user_id, symbol)
);

CREATE TABLE orders (
    id         SERIAL PRIMARY KEY,
    user_id    INTEGER NOT NULL REFERENCES users(id),
    symbol     TEXT NOT NULL,
    side       TEXT NOT NULL,
    quantity   NUMERIC(18, 4) NOT NULL CHECK (quantity > 0),
    price      NUMERIC(18, 2) NOT NULL,
    total      NUMERIC(18, 2) NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- fix (vulnerability 1): idempotency_key makes a retried/duplicated withdrawal a no-op.
-- The partial UNIQUE index guarantees one payout per (user, key) even under
-- concurrent requests.
CREATE TABLE withdrawals (
    id              SERIAL PRIMARY KEY,
    user_id         INTEGER NOT NULL REFERENCES users(id),
    amount          NUMERIC(18, 2) NOT NULL,
    iban            TEXT NOT NULL,
    idempotency_key TEXT,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE UNIQUE INDEX withdrawals_user_idem
    ON withdrawals (user_id, idempotency_key)
    WHERE idempotency_key IS NOT NULL;
