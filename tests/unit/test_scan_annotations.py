"""Tests for scan tags & notes: DB migration, filtering, validation, and the PATCH endpoint."""

import sqlite3
from unittest.mock import patch

import pytest
from fastapi.testclient import TestClient

from api.main import app
from database.scan_history import ScanHistoryDB


def _scan(target, score=5.0, level="MEDIUM"):
    return {
        "target": target,
        "risk_score": score,
        "risk_level": level,
        "vulnerabilities": [{"id": "SSH-001", "title": "Password auth", "severity": "Medium"}],
    }


@pytest.fixture
def db_path(tmp_path):
    return str(tmp_path / "history.db")


@pytest.fixture
def client(db_path):
    with patch("api.routes.history._get_db", lambda: ScanHistoryDB(db_path)):
        yield TestClient(app)


class TestMigration:
    def test_adds_columns_to_pre_v1_1_database(self, db_path):
        # Create the original v1.0 schema without tags/notes and one row.
        conn = sqlite3.connect(db_path)
        conn.execute("""
            CREATE TABLE scans (
                id INTEGER PRIMARY KEY AUTOINCREMENT, target TEXT NOT NULL,
                scan_timestamp TEXT NOT NULL, device_vendor TEXT, device_model TEXT,
                firmware_version TEXT, risk_score REAL NOT NULL, risk_level TEXT NOT NULL,
                vulnerability_count INTEGER NOT NULL, scan_duration REAL,
                full_results TEXT NOT NULL, created_at TEXT NOT NULL)
        """)
        conn.execute(
            "INSERT INTO scans (target, scan_timestamp, risk_score, risk_level, "
            "vulnerability_count, full_results, created_at) "
            "VALUES ('10.0.0.1', '2026-01-01T00:00:00', 3.0, 'LOW', 0, '{}', '2026-01-01')"
        )
        conn.commit()
        conn.close()

        with ScanHistoryDB(db_path) as db:
            scans = db.get_all_scans()
            assert scans[0]["tags"] == [] and scans[0]["notes"] == ""
            assert db.update_annotations(scans[0]["id"], tags=["legacy"])
            assert db.get_scan_summary(scans[0]["id"])["tags"] == ["legacy"]

    def test_migration_is_idempotent(self, db_path):
        ScanHistoryDB(db_path).close()
        ScanHistoryDB(db_path).close()  # second open must not re-add columns


class TestDatabaseAnnotations:
    def test_update_and_partial_update(self, db_path):
        with ScanHistoryDB(db_path) as db:
            sid = db.save_scan(_scan("10.0.0.1"))
            assert db.update_annotations(sid, tags=["pre-patch"], notes="before fw 1.2")
            assert db.update_annotations(sid, notes="after reboot")  # tags untouched
            summary = db.get_scan_summary(sid)
            assert summary["tags"] == ["pre-patch"]
            assert summary["notes"] == "after reboot"

    def test_update_missing_scan(self, db_path):
        with ScanHistoryDB(db_path) as db:
            assert db.update_annotations(999, tags=["x"]) is False
            assert db.update_annotations(999) is False

    def test_tag_filter_is_case_insensitive_and_before_limit(self, db_path):
        with ScanHistoryDB(db_path) as db:
            tagged = db.save_scan(_scan("10.0.0.1"))
            db.update_annotations(tagged, tags=["Pre-Patch"])
            for _ in range(5):
                db.save_scan(_scan("10.0.0.2"))  # newer, untagged
            scans = db.get_all_scans(limit=2, tag="pre-patch")
            assert [s["id"] for s in scans] == [tagged]

    def test_target_and_risk_filters_apply_before_limit(self, db_path):
        with ScanHistoryDB(db_path) as db:
            old = db.save_scan(_scan("10.0.0.1", level="HIGH"))
            for _ in range(3):
                db.save_scan(_scan("10.0.0.2"))
            assert [s["id"] for s in db.get_all_scans(limit=1, target="10.0.0.1")] == [old]
            assert [s["id"] for s in db.get_all_scans(limit=1, risk_level="HIGH")] == [old]

    def test_get_all_tags(self, db_path):
        with ScanHistoryDB(db_path) as db:
            a = db.save_scan(_scan("10.0.0.1"))
            b = db.save_scan(_scan("10.0.0.2"))
            db.update_annotations(a, tags=["post-update", "lab"])
            db.update_annotations(b, tags=["lab", "Baseline"])
            assert db.get_all_tags() == ["Baseline", "lab", "post-update"]


class TestAnnotationEndpoint:
    def test_patch_sets_tags_and_notes(self, client, db_path):
        with ScanHistoryDB(db_path) as db:
            sid = db.save_scan(_scan("10.0.0.1"))

        response = client.patch(
            f"/api/history/{sid}",
            json={"tags": [" pre-patch ", "PRE-PATCH", "lab  bench"], "notes": "fw 1.2.3"},
        )
        assert response.status_code == 200
        data = response.json()
        assert data["tags"] == ["pre-patch", "lab bench"]  # trimmed, collapsed, deduped
        assert data["notes"] == "fw 1.2.3"

        listed = client.get("/api/history?tag=lab%20bench").json()
        assert [s["id"] for s in listed] == [sid]
        assert client.get("/api/history/tags").json() == ["lab bench", "pre-patch"]

    def test_patch_missing_scan(self, client):
        assert client.patch("/api/history/999", json={"notes": "x"}).status_code == 404

    def test_patch_rejects_too_many_tags(self, client, db_path):
        with ScanHistoryDB(db_path) as db:
            sid = db.save_scan(_scan("10.0.0.1"))
        response = client.patch(f"/api/history/{sid}", json={"tags": [f"t{i}" for i in range(11)]})
        assert response.status_code == 422

    def test_patch_rejects_long_tag_and_notes(self, client, db_path):
        with ScanHistoryDB(db_path) as db:
            sid = db.save_scan(_scan("10.0.0.1"))
        assert client.patch(f"/api/history/{sid}", json={"tags": ["x" * 33]}).status_code == 422
        assert client.patch(f"/api/history/{sid}", json={"notes": "x" * 2001}).status_code == 422

    def test_empty_tags_clear(self, client, db_path):
        with ScanHistoryDB(db_path) as db:
            sid = db.save_scan(_scan("10.0.0.1"))
            db.update_annotations(sid, tags=["a"])
        response = client.patch(f"/api/history/{sid}", json={"tags": ["  ", ""]})
        assert response.json()["tags"] == []


def test_concurrent_first_open_migrates_once(tmp_path):
    """Parallel scans opening a pre-v1.1 database must not race on ALTER TABLE."""
    import sqlite3
    import threading

    from database.scan_history import ScanHistoryDB

    db_path = tmp_path / "old.db"
    ScanHistoryDB(str(db_path)).close()
    conn = sqlite3.connect(db_path)
    # Rebuild the scans table without the v1.1 columns.
    cols = [r[1] for r in conn.execute("PRAGMA table_info(scans)") if r[1] not in ("tags", "notes")]
    conn.executescript(
        f"CREATE TABLE s2 AS SELECT {', '.join(cols)} FROM scans; DROP TABLE scans; ALTER TABLE s2 RENAME TO scans;"
    )
    conn.close()

    errors, barrier = [], threading.Barrier(6)

    def opener():
        barrier.wait()
        try:
            ScanHistoryDB(str(db_path)).close()
        except Exception as e:  # pragma: no cover - the regression
            errors.append(e)

    threads = [threading.Thread(target=opener) for _ in range(6)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert errors == []
    names = {r[1] for r in sqlite3.connect(db_path).execute("PRAGMA table_info(scans)")}
    assert {"tags", "notes"} <= names
