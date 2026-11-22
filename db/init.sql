-- schema (intentionally vulnerable training app)

CREATE TABLE users (
    id            SERIAL PRIMARY KEY,
    username      TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    iban          TEXT,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- NOTE: no CHECK (balance >= 0) on purpose. Adding it is part of the fix.
CREATE TABLE accounts (
    user_id  INTEGER PRIMARY KEY REFERENCES users(id),
    balance  NUMERIC(18, 2) NOT NULL DEFAULT 0
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
    quantity   NUMERIC(18, 4) NOT NULL,
    price      NUMERIC(18, 2) NOT NULL,
    total      NUMERIC(18, 2) NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- NOTE: no idempotency_key column yet. Adding it (with a UNIQUE index) is part of the fix.
CREATE TABLE withdrawals (
    id         SERIAL PRIMARY KEY,
    user_id    INTEGER NOT NULL REFERENCES users(id),
    amount     NUMERIC(18, 2) NOT NULL,
    iban       TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
