import os
from datetime import datetime, timedelta, timezone

import bcrypt
import jwt
from fastapi import Depends, HTTPException
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer


def _load_jwt_secret() -> str:
    # FIX (weak JWT secret): this used to fall back to "dev-only" when the
    # variable was missing, so a deploy that forgot it signed tokens with a key
    # anyone can read in this repo, and anyone could forge a login. Now the app
    # refuses to start instead.
    secret = os.environ.get("JWT_SECRET", "")
    placeholders = {"dev-only", "dev-only-change-me", "change-me-to-a-long-random-value"}
    if len(secret) < 32 or secret in placeholders:
        raise RuntimeError(
            "JWT_SECRET must be set to a random value of at least 32 characters, "
            "e.g. python -c 'import secrets; print(secrets.token_urlsafe(32))'"
        )
    return secret


JWT_SECRET = _load_jwt_secret()
JWT_ALG = "HS256"
TOKEN_TTL = timedelta(hours=1)

bearer = HTTPBearer()


def hash_password(password: str) -> str:
    return bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()


def verify_password(password: str, password_hash: str) -> bool:
    return bcrypt.checkpw(password.encode(), password_hash.encode())


def create_token(user_id: int, username: str) -> str:
    now = datetime.now(timezone.utc)
    payload = {"sub": str(user_id), "username": username, "iat": now, "exp": now + TOKEN_TTL}
    return jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALG)


def current_user(creds: HTTPAuthorizationCredentials = Depends(bearer)) -> dict:
    try:
        payload = jwt.decode(creds.credentials, JWT_SECRET, algorithms=[JWT_ALG])
    except jwt.PyJWTError:
        raise HTTPException(status_code=401, detail="Invalid or expired token")
    return {"id": int(payload["sub"]), "username": payload["username"]}
