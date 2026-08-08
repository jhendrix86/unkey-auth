import httpx
import pytest
import respx
from fastapi import Depends, FastAPI
from fastapi.testclient import TestClient

from unkey_auth import middleware as middleware_module
from unkey_auth.client import UnkeyClient
from unkey_auth.config import Config
from unkey_auth.middleware import require_api_key


def make_app():
    app = FastAPI()

    @app.get("/protected", dependencies=[Depends(require_api_key)])
    async def protected():
        return {"ok": True}

    return TestClient(app)


@pytest.fixture(autouse=True)
def reset_singleton_client(monkeypatch):
    # get_client() memoizes a module-level singleton; force each test to
    # build a fresh one from whatever config the test sets up.
    monkeypatch.setattr(middleware_module, "_client", None)
    monkeypatch.setattr(middleware_module, "_warned_disabled", False)
    yield


class TestFailsOpenWhenUnconfigured:
    def test_allows_request_without_header_when_no_root_key(self, monkeypatch):
        monkeypatch.delenv("UNKEY_ROOT_KEY", raising=False)
        client = make_app()

        response = client.get("/protected")

        assert response.status_code == 200
        assert response.json() == {"ok": True}


class TestEnforcesWhenConfigured:
    def _configure(self, monkeypatch):
        monkeypatch.setattr(
            middleware_module,
            "_client",
            UnkeyClient(Config(unkey_root_key="root_test", unkey_base_url="https://api.unkey.com/v2")),
        )

    def test_missing_header_returns_401(self, monkeypatch):
        self._configure(monkeypatch)
        client = make_app()

        response = client.get("/protected")

        assert response.status_code == 401

    def test_malformed_header_returns_401(self, monkeypatch):
        self._configure(monkeypatch)
        client = make_app()

        response = client.get("/protected", headers={"Authorization": "NotBearer abc"})

        assert response.status_code == 401

    @respx.mock
    def test_valid_key_returns_200(self, monkeypatch):
        self._configure(monkeypatch)
        respx.post("https://api.unkey.com/v2/keys.verifyKey").mock(
            return_value=httpx.Response(200, json={"meta": {}, "data": {"valid": True, "code": "VALID"}})
        )
        client = make_app()

        response = client.get("/protected", headers={"Authorization": "Bearer unkey_live_abc"})

        assert response.status_code == 200

    @respx.mock
    def test_invalid_key_returns_401(self, monkeypatch):
        self._configure(monkeypatch)
        respx.post("https://api.unkey.com/v2/keys.verifyKey").mock(
            return_value=httpx.Response(200, json={"meta": {}, "data": {"valid": False, "code": "NOT_FOUND"}})
        )
        client = make_app()

        response = client.get("/protected", headers={"Authorization": "Bearer bogus"})

        assert response.status_code == 401

    @respx.mock
    def test_rate_limited_key_returns_429(self, monkeypatch):
        self._configure(monkeypatch)
        respx.post("https://api.unkey.com/v2/keys.verifyKey").mock(
            return_value=httpx.Response(200, json={"meta": {}, "data": {"valid": False, "code": "RATE_LIMITED"}})
        )
        client = make_app()

        response = client.get("/protected", headers={"Authorization": "Bearer unkey_live_abc"})

        assert response.status_code == 429

    @respx.mock
    def test_unreachable_unkey_api_returns_503(self, monkeypatch):
        self._configure(monkeypatch)
        respx.post("https://api.unkey.com/v2/keys.verifyKey").mock(
            side_effect=httpx.ConnectError("connection refused")
        )
        client = make_app()

        response = client.get("/protected", headers={"Authorization": "Bearer unkey_live_abc"})

        assert response.status_code == 503
