"""Tests for the detection rules + engine.

    cd detections && python -m unittest -v

Synthetic tests pin each rule's threshold and near-miss cases. The sample
tests check the captured logs give the expected alerts on each branch.
"""
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

from detect import detect, load_events

HERE = Path(__file__).parent
T0 = datetime(2026, 11, 22, 12, 0, 0, tzinfo=timezone.utc)


def ev(event, seconds=0.0, **fields):
    ts = T0 + timedelta(seconds=seconds)
    return {"event": event, "ts": ts.isoformat(), "_ts": ts, **fields}


def fired(events):
    alerts, _, _ = detect(sorted(events, key=lambda e: e["_ts"]))
    return [a.rule.title for a in alerts]


def count(events, prefix):
    return sum(t.startswith(prefix) for t in fired(events))


class CredentialAttacks(unittest.TestCase):
    def test_stuffing_three_accounts_one_ip(self):
        evs = [ev("login_failed", i, user=u, ip="45.1.1.1") for i, u in enumerate(["a", "b", "c"])]
        self.assertEqual(count(evs, "Credential stuffing"), 1)

    def test_two_accounts_is_not_stuffing(self):
        evs = [ev("login_failed", i, user=u, ip="45.1.1.1") for i, u in enumerate(["a", "b"])]
        self.assertEqual(count(evs, "Credential stuffing"), 0)

    def test_same_users_from_different_ips_is_not_stuffing(self):
        evs = [ev("login_failed", i, user=u, ip=f"10.0.0.{i}") for i, u in enumerate("abcde")]
        self.assertEqual(count(evs, "Credential stuffing"), 0)

    def test_stuffing_outside_window(self):
        evs = [ev("login_failed", i * 200, user=u, ip="45.1.1.1") for i, u in enumerate("abc")]
        self.assertEqual(count(evs, "Credential stuffing"), 0)

    def test_password_guessing_threshold(self):
        evs = [ev("login_failed", i, user="ali", ip="45.1.1.1") for i in range(4)]
        self.assertEqual(count(evs, "Password guessing"), 0)
        evs.append(ev("login_failed", 5, user="ali", ip="45.1.1.1"))
        self.assertEqual(count(evs, "Password guessing"), 1)

    def test_single_failed_login_is_silent(self):
        self.assertEqual(fired([ev("login_failed", user="ali", ip="1.2.3.4")]), [])


class AccountTakeover(unittest.TestCase):
    def chain(self, country="RU", gap=60):
        return [
            ev("login_success", 0, user="z", country="TR"),          # baseline
            ev("login_success", 100, user="z", country=country),
            ev("iban_changed", 100 + gap, user="z"),
            ev("withdraw", 100 + 2 * gap, user="z", amount="900.00"),
        ]

    def test_full_chain(self):
        self.assertEqual(count(self.chain(), "Account takeover"), 1)

    def test_known_country_is_not_takeover(self):
        self.assertEqual(count(self.chain(country="TR"), "Account takeover"), 0)

    def test_first_ever_login_is_baseline_not_new(self):
        evs = self.chain()[1:]  # the RU login is now this user's first
        self.assertEqual(count(evs, "Account takeover"), 0)

    def test_chain_too_slow(self):
        self.assertEqual(count(self.chain(gap=600), "Account takeover"), 0)

    def test_wrong_order(self):
        evs = self.chain()
        evs[2]["_ts"], evs[3]["_ts"] = evs[3]["_ts"], evs[2]["_ts"]  # withdraw before IBAN change
        self.assertEqual(count(evs, "Account takeover"), 0)

    def test_other_users_steps_dont_combine(self):
        evs = self.chain()
        evs[2]["user"] = "someone_else"
        self.assertEqual(count(evs, "Account takeover"), 0)


class WithdrawalBurst(unittest.TestCase):
    def test_burst_counts_rejected_attempts(self):
        evs = [ev("withdraw", 0, user="veli")] + [
            ev("withdraw_rejected", 0.01 * i, user="veli", reason="insufficient_balance")
            for i in range(1, 20)]
        alerts, _, _ = detect(evs)
        burst = [a for a in alerts if a.rule.title.startswith("Withdrawal burst")]
        self.assertEqual(len(burst), 1)
        self.assertEqual(burst[0].value, 20)  # the whole burst, not just the threshold

    def test_spread_out_withdrawals(self):
        evs = [ev("withdraw", 2 * i, user="veli") for i in range(10)]
        self.assertEqual(count(evs, "Withdrawal burst"), 0)


class OrderAccess(unittest.TestCase):
    def test_reading_someone_elses_order(self):
        self.assertEqual(count([ev("order_read", user="ali", order_owner="veli")], "IDOR"), 1)

    def test_reading_own_order(self):
        self.assertEqual(count([ev("order_read", user="ali", order_owner="ALI")], "IDOR"), 0)

    def test_fixed_app_read_without_owner_field(self):
        self.assertEqual(count([ev("order_read", user="ali")], "IDOR"), 0)

    def test_enumeration(self):
        evs = [ev("order_read_denied", i, user="ali", order_id=i) for i in range(10)]
        self.assertEqual(count(evs, "Order ID enumeration"), 1)
        self.assertEqual(count(evs[:9], "Order ID enumeration"), 0)


class Samples(unittest.TestCase):
    """The committed sample logs, captured from real runs."""

    def run_sample(self, name):
        path = HERE / "samples" / f"{name}.jsonl"
        if not path.exists():
            self.skipTest(f"{path} not generated")
        with open(path) as f:
            return fired(load_events(f))

    def assert_fires(self, titles, prefix):
        self.assertTrue(any(t.startswith(prefix) for t in titles), f"{prefix!r} did not fire")

    def test_main(self):
        titles = self.run_sample("main")
        for p in ["Credential stuffing", "Password guessing", "Login rate limit",
                  "Account takeover", "Withdrawal burst", "Order ID enumeration"]:
            self.assert_fires(titles, p)
        self.assertFalse(any(t.startswith("IDOR") for t in titles), "fixed app cannot leak orders")
        self.assertEqual(sum(t.startswith("Account takeover") for t in titles), 1,
                         "only the attacked user, not the benign look-alikes")

    def test_vulnerable(self):
        titles = self.run_sample("vulnerable")
        for p in ["Credential stuffing", "Account takeover", "Withdrawal burst", "IDOR"]:
            self.assert_fires(titles, p)
        self.assertFalse(any(t.startswith("Login rate limit") for t in titles),
                         "vulnerable app has no rate limiter")


if __name__ == "__main__":
    unittest.main()
