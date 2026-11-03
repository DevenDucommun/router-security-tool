"""Runtime-location overrides used by the Docker image.

The image pip-installs the package into site-packages, where the repo-relative
defaults (web/dist next to src/) do not exist. These env vars let it serve the
SPA and listen on a published port.
"""

import importlib
from unittest.mock import patch

from fastapi.testclient import TestClient


def _reload_main():
    import api.main

    return importlib.reload(api.main)


def test_web_dist_override_serves_spa(tmp_path, monkeypatch):
    dist = tmp_path / "dist"
    (dist / "assets").mkdir(parents=True)
    (dist / "index.html").write_text('<div id="root"></div>')
    (dist / "assets" / "app.js").write_text("console.log(1)")
    monkeypatch.setenv("ROUTER_SECURITY_WEB_DIST", str(dist))
    try:
        client = TestClient(_reload_main().app)
        assert 'id="root"' in client.get("/").text
        assert 'id="root"' in client.get("/history").text  # SPA fallback
        assert client.get("/assets/app.js").status_code == 200
        assert client.get("/api/health").json()["status"] == "ok"
    finally:
        monkeypatch.delenv("ROUTER_SECURITY_WEB_DIST")
        _reload_main()


def test_missing_web_dist_still_serves_api(tmp_path, monkeypatch):
    monkeypatch.setenv("ROUTER_SECURITY_WEB_DIST", str(tmp_path / "nope"))
    try:
        client = TestClient(_reload_main().app)
        assert client.get("/api/health").status_code == 200
        assert client.get("/").status_code == 404
    finally:
        monkeypatch.delenv("ROUTER_SECURITY_WEB_DIST")
        _reload_main()


def test_server_defaults_to_loopback(monkeypatch):
    monkeypatch.delenv("ROUTER_SECURITY_HOST", raising=False)
    monkeypatch.delenv("ROUTER_SECURITY_PORT", raising=False)
    from api import server

    with patch.object(server.uvicorn, "run") as run:
        server.main()
    assert run.call_args.kwargs["host"] == "127.0.0.1"
    assert run.call_args.kwargs["port"] == 8000


def test_server_host_and_port_overrides(monkeypatch):
    monkeypatch.setenv("ROUTER_SECURITY_HOST", "0.0.0.0")
    monkeypatch.setenv("ROUTER_SECURITY_PORT", "9001")
    from api import server

    with patch.object(server.uvicorn, "run") as run:
        server.main()
    assert run.call_args.kwargs["host"] == "0.0.0.0"
    assert run.call_args.kwargs["port"] == 9001
