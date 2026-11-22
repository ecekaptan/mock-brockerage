"""Drive the running app with traffic the exploit scripts don't produce, so the
captured log covers every rule. It includes benign look-alikes the rules must NOT
fire on.

Every actor gets its own client IP through X-Forwarded-For. The vulnerable app
trusts that header outright. The fixed app does only when started with
TRUSTED_PROXY_HOPS=1 (simulating a load balancer), which generate_sample.sh
does. Fake data only; run against a local instance.

    TARGET=http://localhost:8000 python scenarios.py
"""
import os
import uuid

import httpx

BASE = os.environ.get("TARGET", "http://localhost:8000")
RUN = uuid.uuid4().hex[:6]  # unique usernames per run
PASSWORD = "Password123!"


class Client:
    """One actor: a fixed source IP and country."""

    def __init__(self, ip: str, country: str):
        self.http = httpx.Client(base_url=BASE, timeout=30,
                                 headers={"X-Forwarded-For": ip, "X-Client-Country": country})
        self.token = None

    def register(self, username: str):
        self.http.post("/register", json={"username": username, "password": PASSWORD})

    def login(self, username: str, password: str = PASSWORD) -> int:
        r = self.http.post("/login", json={"username": username, "password": password})
        if r.status_code == 200:
            self.token = r.json()["access_token"]
            self.http.headers["Authorization"] = f"Bearer {self.token}"
        return r.status_code

    def set_iban(self, iban: str):
        self.http.put("/me/iban", json={"iban": iban}).raise_for_status()

    def withdraw(self, amount: int) -> int:
        return self.http.post("/withdraw", json={"amount": amount}).status_code


def benign_customer():
    """Mistypes once, logs in from home (TR), changes IBAN, withdraws.
    Has every step of the takeover chain except the new country → no alert."""
    name = f"ayse_{RUN}"
    c = Client("88.230.10.21", "TR")
    c.register(name)
    c.login(name, "Pasword123!")   # one typo: must not look like brute force
    c.login(name)
    c.set_iban("TR000000000000000000000101")
    c.withdraw(100)
    print(f"[benign] {name}: typo, TR login, IBAN change, withdraw 100")


def traveller():
    """Logs in at home, later from Germany, and only checks the balance.
    A new country with no IBAN change → no takeover alert."""
    name = f"mehmet_{RUN}"
    home, abroad = Client("88.230.10.33", "TR"), Client("91.64.7.12", "DE")
    home.register(name)
    home.login(name)
    abroad.login(name)
    abroad.http.get("/me")
    print(f"[benign] {name}: TR login, then DE login, no money movement")


def account_takeover():
    """Victim logs in from TR. Attacker with the stolen password logs in from
    RU, points the payout IBAN at their own account, and withdraws."""
    name = f"zeynep_{RUN}"
    victim = Client("88.230.10.47", "TR")
    victim.register(name)
    victim.login(name)
    victim.set_iban("TR000000000000000000000202")

    attacker = Client("185.220.101.4", "RU")
    attacker.login(name)
    attacker.set_iban("TR666666666666666666666666")
    status = attacker.withdraw(900)
    print(f"[attack] {name}: RU login → IBAN change → withdraw 900 (HTTP {status})")


def credential_stuffing():
    """One IP tries leaked username/password pairs against several accounts."""
    attacker = Client("45.155.205.9", "NL")
    leaked = [("ali", "ali1987"), ("veli", "Galatasaray1905"), ("ayse", "qwerty123"),
              ("mehmet", "Istanbul34"), ("fatma", "123456")]
    codes = [attacker.login(u, p) for u, p in leaked]
    print(f"[attack] credential stuffing from 45.155.205.9: {codes}")


if __name__ == "__main__":
    print(f"[*] Target: {BASE}  run={RUN}")
    benign_customer()
    traveller()
    account_takeover()
    credential_stuffing()
