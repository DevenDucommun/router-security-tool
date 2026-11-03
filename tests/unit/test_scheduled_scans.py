"""Scheduled scans: credential vault, schedule store, scheduler, and API."""

import asyncio
import os
import stat
import threading
import time
from datetime import timedelta

import pytest
from cryptography.fernet import Fernet
from fastapi.testclient import TestClient

from api import scheduler as sched_mod
from api.scheduler import Scheduler
from database.credentials import CredentialError, CredentialVault, default_key_file
from database.schedules import ScheduleStore, iso, utcnow


# --------------------------------------------------------------------------- #
# CredentialVault
# --------------------------------------------------------------------------- #


class TestCredentialVault:
    def test_roundtrip_and_ciphertext_hides_secret(self, tmp_path):
        v = CredentialVault(key_file=tmp_path / "k")
        token = v.encrypt("hunter2")
        assert "hunter2" not in token
        assert v.decrypt(token) == "hunter2"

    def test_key_file_created_0600_and_reused(self, tmp_path):
        kf = tmp_path / "sub" / "secret.key"
        v1 = CredentialVault(key_file=kf)
        assert v1.key_source == "file"
        assert stat.S_IMODE(os.stat(kf).st_mode) == 0o600
        token = v1.encrypt("pw")
        assert CredentialVault(key_file=kf).decrypt(token) == "pw"

    def test_default_key_file_sits_next_to_history_db(self, isolated_history_db):
        assert default_key_file() == isolated_history_db.parent / "secret.key"

    def test_env_key_wins(self, tmp_path, monkeypatch):
        key = Fernet.generate_key()
        monkeypatch.setenv("ROUTER_SECURITY_SECRET_KEY", key.decode())
        v = CredentialVault(key_file=tmp_path / "unused")
        assert v.key_source == "env"
        assert not (tmp_path / "unused").exists()
        assert Fernet(key).decrypt(v.encrypt("x").encode()) == b"x"

    def test_invalid_env_key(self, monkeypatch):
        monkeypatch.setenv("ROUTER_SECURITY_SECRET_KEY", "not-a-key")
        with pytest.raises(CredentialError, match="Fernet key"):
            CredentialVault()

    def test_wrong_key_or_garbage_token(self, tmp_path):
        token = CredentialVault(key=Fernet.generate_key()).encrypt("pw")
        other = CredentialVault(key=Fernet.generate_key())
        with pytest.raises(CredentialError, match="re-enter"):
            other.decrypt(token)
        with pytest.raises(CredentialError):
            other.decrypt("garbage")


# --------------------------------------------------------------------------- #
# ScheduleStore
# --------------------------------------------------------------------------- #


@pytest.fixture
def store(tmp_path):
    return ScheduleStore(tmp_path / "h.db")


def _mk(store, **kw):
    args = dict(target="10.0.0.1", username="root", credential="tok", interval_minutes=60)
    args.update(kw)
    return store.create(**args)


class TestScheduleStore:
    def test_crud(self, store):
        s = _mk(store, name="lab", tags=["lab"], port=2222)
        assert (s["name"], s["port"], s["tags"], s["enabled"], s["last_status"]) == ("lab", 2222, ["lab"], True, "never")
        assert store.get(s["id"])["target"] == "10.0.0.1"
        assert [x["id"] for x in store.list()] == [s["id"]]
        u = store.update(s["id"], enabled=False, tags=["a", "b"])
        assert u["enabled"] is False and u["tags"] == ["a", "b"]
        assert store.update(999, enabled=True) is None
        with pytest.raises(ValueError):
            store.update(s["id"], target="evil")  # not updatable
        assert store.delete(s["id"]) and not store.delete(s["id"])

    def test_claim_due_only_due_enabled_idle(self, store):
        now = utcnow()
        due = _mk(store, first_run_at=now - timedelta(minutes=1))
        _mk(store, first_run_at=now + timedelta(hours=1))  # not due
        _mk(store, first_run_at=now - timedelta(minutes=1), enabled=False)  # disabled
        claimed = store.claim_due(now)
        assert [c["id"] for c in claimed] == [due["id"]]
        row = store.get(due["id"])
        assert row["running"] and row["last_status"] == "running"
        assert row["next_run_at"] == iso(now + timedelta(minutes=60))
        # Already running: not claimed again even after its next slot passes.
        later = [c["id"] for c in store.claim_due(now + timedelta(hours=2))]
        assert due["id"] not in later

    def test_missed_runs_collapse_to_one(self, store):
        now = utcnow()
        s = _mk(store, first_run_at=now - timedelta(days=7))  # down for a week, hourly
        assert len(store.claim_due(now)) == 1
        store.finish(s["id"], status="ok")
        assert store.claim_due(now) == []  # next is now+1h, not the next missed slot

    def test_concurrent_claims_never_double_run(self, store):
        now = utcnow()
        ids = {_mk(store, first_run_at=now - timedelta(minutes=1))["id"] for _ in range(20)}
        results, barrier = [], threading.Barrier(4)

        def worker():
            barrier.wait()
            results.extend(c["id"] for c in ScheduleStore(store.path).claim_due(now))

        threads = [threading.Thread(target=worker) for _ in range(4)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        assert sorted(results) == sorted(ids)  # each exactly once

    def test_claim_and_finish_and_reset(self, store):
        s = _mk(store, first_run_at=utcnow() + timedelta(hours=5))
        next_before = s["next_run_at"]
        claimed = store.claim(s["id"])
        assert claimed["running"] and claimed["next_run_at"] == next_before  # run-now keeps the slot
        assert store.claim(s["id"]) is None  # busy
        store.finish(s["id"], status="ok", scan_id=7, risk_score=3.5)
        row = store.get(s["id"])
        assert (row["running"], row["last_status"], row["last_scan_id"], row["last_risk_score"]) == (False, "ok", 7, 3.5)
        assert row["last_run_at"]
        store.claim(s["id"])
        assert store.reset_running() == 1
        row = store.get(s["id"])
        assert not row["running"] and "restart" in row["last_error"]
        assert store.claim(999) is None


# --------------------------------------------------------------------------- #
# Scheduler
# --------------------------------------------------------------------------- #


@pytest.fixture
def vault():
    return CredentialVault(key=Fernet.generate_key())


def _save_history_scan():
    from database.scan_history import ScanHistoryDB

    with ScanHistoryDB() as db:
        return db.save_scan({
            "target": "10.0.0.1", "device_info": {"vendor": "openwrt", "product": "r", "version": "1"},
            "risk_score": 4.2, "risk_level": "MEDIUM", "scan_duration": 1.0, "vulnerabilities": [],
        })


class TestSchedulerExecute:
    def test_success_tags_scan_and_records(self, store, vault):
        calls = []

        def run_scan(host, port, user, pw):
            calls.append((host, port, user, pw))
            return _save_history_scan(), 4.2

        s = _mk(store, credential=vault.encrypt("s3cret"), tags=["lab", "scheduled"], port=2200)
        sch = Scheduler(store=store, vault=vault, run_scan=run_scan)
        out = sch.execute(store.claim(s["id"]))
        assert out["status"] == "ok"
        assert calls == [("10.0.0.1", 2200, "root", "s3cret")]
        row = store.get(s["id"])
        assert (row["last_status"], row["last_scan_id"], row["last_risk_score"], row["running"]) == (
            "ok", out["scan_id"], 4.2, False)

        from database.scan_history import ScanHistoryDB

        with ScanHistoryDB() as db:
            assert db.get_scan_summary(out["scan_id"])["tags"] == ["scheduled", "lab"]

    def test_connection_error(self, store, vault):
        def run_scan(*a):
            raise ConnectionError("SSH connection to 10.0.0.1:22 failed")

        s = _mk(store, credential=vault.encrypt("pw"))
        out = Scheduler(store=store, vault=vault, run_scan=run_scan).execute(store.claim(s["id"]))
        row = store.get(s["id"])
        assert out["status"] == "error" and row["last_status"] == "error" and not row["running"]
        assert "SSH connection" in row["last_error"]

    def test_unexpected_exception_is_contained(self, store, vault):
        def run_scan(*a):
            raise RuntimeError("boom")

        s = _mk(store, credential=vault.encrypt("pw"))
        Scheduler(store=store, vault=vault, run_scan=run_scan).execute(store.claim(s["id"]))
        assert "boom" in store.get(s["id"])["last_error"]

    def test_undecryptable_credential(self, store, vault):
        called = []
        s = _mk(store, credential=CredentialVault(key=Fernet.generate_key()).encrypt("pw"))
        Scheduler(store=store, vault=vault, run_scan=lambda *a: called.append(1)).execute(store.claim(s["id"]))
        row = store.get(s["id"])
        assert called == [] and row["last_status"] == "error" and "re-enter" in row["last_error"]

    def test_persist_failure(self, store, vault):
        s = _mk(store, credential=vault.encrypt("pw"))
        Scheduler(store=store, vault=vault, run_scan=lambda *a: (None, 1.0)).execute(store.claim(s["id"]))
        assert "could not be saved" in store.get(s["id"])["last_error"]


class TestSchedulerLoop:
    def test_tick_runs_due_with_concurrency_limit(self, store, vault):
        active, peak, lock = [0], [0], threading.Lock()

        def run_scan(*a):
            with lock:
                active[0] += 1
                peak[0] = max(peak[0], active[0])
            time.sleep(0.05)
            with lock:
                active[0] -= 1
            return _save_history_scan(), 1.0

        now = utcnow()
        ids = [_mk(store, credential=vault.encrypt("pw"), first_run_at=now - timedelta(minutes=1))["id"] for _ in range(5)]

        async def go():
            sch = Scheduler(store=store, vault=vault, run_scan=run_scan, max_concurrent=2)
            tasks = await sch.tick()
            await asyncio.gather(*tasks)
            return len(tasks)

        assert asyncio.run(go()) == 5
        assert peak[0] == 2
        assert all(store.get(i)["last_status"] == "ok" for i in ids)

    def test_run_now_busy_returns_none(self, store, vault):
        s = _mk(store, credential=vault.encrypt("pw"))
        store.claim(s["id"])

        async def go():
            return await Scheduler(store=store, vault=vault).run_now(s["id"])

        assert asyncio.run(go()) is None

    def test_start_resets_stale_and_stop(self, store, vault):
        s = _mk(store, credential=vault.encrypt("pw"), first_run_at=utcnow() + timedelta(hours=1))
        store.claim(s["id"])

        async def go():
            sch = Scheduler(store=store, vault=vault, poll_seconds=0.01)
            sch.start()
            await asyncio.sleep(0.03)
            assert sch.running
            await sch.stop()
            return sch.running

        assert asyncio.run(go()) is False
        assert store.get(s["id"])["running"] is False

    def test_scheduler_enabled_env(self, monkeypatch):
        monkeypatch.setenv("ROUTER_SECURITY_SCHEDULER", "0")
        assert not sched_mod.scheduler_enabled()
        monkeypatch.setenv("ROUTER_SECURITY_SCHEDULER", "1")
        assert sched_mod.scheduler_enabled()
        monkeypatch.delenv("ROUTER_SECURITY_SCHEDULER")
        assert sched_mod.scheduler_enabled()


# --------------------------------------------------------------------------- #
# API
# --------------------------------------------------------------------------- #


@pytest.fixture
def client():
    from api.main import app

    return TestClient(app)


@pytest.fixture
def fake_scheduler(monkeypatch):
    """Record run-now calls instead of SSHing anywhere."""
    started = []

    class Fake(Scheduler):
        async def run_now(self, schedule_id):
            claimed = await asyncio.to_thread(self.store.claim, schedule_id)
            if not claimed:
                return None
            started.append(schedule_id)
            return asyncio.get_running_loop().create_future()

    sched_mod.set_scheduler(Fake())
    return started


BODY = {"target": "192.168.1.1", "username": "root", "password": "Pa55word!", "interval_minutes": 1440}


class TestScheduleApi:
    def test_create_list_never_exposes_password(self, client, isolated_history_db):
        r = client.post("/api/schedules", json={**BODY, "tags": ["lab", " lab ", ""], "name": "Home"})
        assert r.status_code == 201, r.text
        s = r.json()
        assert "password" not in s and "credential" not in s and s["has_credential"]
        assert s["tags"] == ["lab"] and s["last_status"] == "never"
        assert s["next_run_at"] > s["created_at"]  # first run one interval out

        listing = client.get("/api/schedules").json()
        assert listing["key_source"] == "file"  # created on first encrypt
        assert listing["enabled"] is False  # tests disable the worker
        assert [x["id"] for x in listing["schedules"]] == [s["id"]]
        assert "Pa55word!" not in r.text + client.get("/api/schedules").text
        # Not stored in plaintext anywhere in the database file.
        assert b"Pa55word!" not in isolated_history_db.read_bytes()

    def test_key_source_before_any_schedule(self, client):
        assert client.get("/api/schedules").json()["key_source"] == "not_created"

    @pytest.mark.parametrize("patch", [
        {"interval_minutes": 5},
        {"interval_minutes": 60 * 24 * 31},
        {"target": "10.0.0.0/24"},
        {"target": "a b"},
        {"port": 0},
        {"password": ""},
        {"tags": [f"t{i}" for i in range(10)]},
        {"tags": ["x" * 33]},
    ])
    def test_validation(self, client, patch):
        assert client.post("/api/schedules", json={**BODY, **patch}).status_code == 422

    def test_update_password_interval_enable(self, client):
        s = client.post("/api/schedules", json=BODY).json()
        sid = s["id"]
        store = ScheduleStore()
        token_before = store.get(sid)["credential"]

        r = client.patch(f"/api/schedules/{sid}", json={"password": "newpass"})
        assert r.status_code == 200 and "newpass" not in r.text
        token_after = store.get(sid)["credential"]
        assert token_after != token_before
        assert CredentialVault().decrypt(token_after) == "newpass"

        r = client.patch(f"/api/schedules/{sid}", json={"interval_minutes": 60})
        nxt = r.json()["next_run_at"]
        assert nxt <= iso(utcnow() + timedelta(minutes=61))

        client.patch(f"/api/schedules/{sid}", json={"enabled": False})
        store.update(sid, next_run_at=utcnow() - timedelta(days=3))  # stale slot while paused
        r = client.patch(f"/api/schedules/{sid}", json={"enabled": True})
        assert r.json()["next_run_at"] > iso(utcnow())  # re-enable doesn't fire immediately

        assert client.patch("/api/schedules/999", json={"enabled": False}).status_code == 404
        assert client.patch(f"/api/schedules/{sid}", json={"interval_minutes": 1}).status_code == 422

    def test_delete(self, client):
        sid = client.post("/api/schedules", json=BODY).json()["id"]
        assert client.delete(f"/api/schedules/{sid}").status_code == 200
        assert client.delete(f"/api/schedules/{sid}").status_code == 404

    def test_run_now_and_conflict(self, client, fake_scheduler):
        sid = client.post("/api/schedules", json=BODY).json()["id"]
        r = client.post(f"/api/schedules/{sid}/run")
        assert r.status_code == 202 and r.json()["running"] is True
        assert fake_scheduler == [sid]
        assert client.post(f"/api/schedules/{sid}/run").status_code == 409
        assert client.post("/api/schedules/999/run").status_code == 404

    def test_run_immediately(self, client, fake_scheduler):
        s = client.post("/api/schedules", json={**BODY, "run_immediately": True}).json()
        assert fake_scheduler == [s["id"]] and s["running"] is True
        # Regression: the regular slot must be one interval out, or the worker
        # re-runs the schedule on every poll after the immediate run finishes.
        assert s["next_run_at"] >= iso(utcnow() + timedelta(minutes=BODY["interval_minutes"] - 1))
        ScheduleStore().finish(s["id"], status="ok")
        assert ScheduleStore().claim_due() == []

    def test_lifespan_starts_and_stops_worker(self, monkeypatch):
        from api.main import app

        monkeypatch.setenv("ROUTER_SECURITY_SCHEDULER", "1")
        sch = Scheduler(poll_seconds=0.05)
        sched_mod.set_scheduler(sch)
        with TestClient(app) as c:
            assert c.get("/api/schedules").json()["running"] is True
        assert sch.running is False
