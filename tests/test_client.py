import json

import httpx
import pytest
import respx

from unkey_auth.client import UnkeyClient, UnkeyError
from unkey_auth.config import Config


def make_client(root_key="root_test_key"):
    config = Config(unkey_root_key=root_key, unkey_base_url="https://api.unkey.com/v2")
    return UnkeyClient(config)


class TestVerifyKey:
    @pytest.mark.asyncio
    async def test_raises_when_not_configured(self):
        client = UnkeyClient(Config(unkey_root_key=""))

        with pytest.raises(UnkeyError):
            await client.verify_key("some_key")

    @pytest.mark.asyncio
    @respx.mock
    async def test_valid_key_parses_result(self):
        respx.post("https://api.unkey.com/v2/keys.verifyKey").mock(
            return_value=httpx.Response(
                200,
                json={
                    "meta": {"requestId": "req_1"},
                    "data": {"valid": True, "code": "VALID", "keyId": "key_123", "ratelimits": []},
                },
            )
        )
        client = make_client()

        result = await client.verify_key("unkey_live_abc")

        assert result.valid is True
        assert result.code == "VALID"
        assert result.key_id == "key_123"
        assert result.rate_limited is False

    @pytest.mark.asyncio
    @respx.mock
    async def test_invalid_key_parses_result(self):
        respx.post("https://api.unkey.com/v2/keys.verifyKey").mock(
            return_value=httpx.Response(
                200,
                json={"meta": {}, "data": {"valid": False, "code": "NOT_FOUND"}},
            )
        )
        client = make_client()

        result = await client.verify_key("bogus")

        assert result.valid is False
        assert result.code == "NOT_FOUND"

    @pytest.mark.asyncio
    @respx.mock
    async def test_rate_limited_key_is_flagged(self):
        respx.post("https://api.unkey.com/v2/keys.verifyKey").mock(
            return_value=httpx.Response(
                200,
                json={"meta": {}, "data": {"valid": False, "code": "RATE_LIMITED"}},
            )
        )
        client = make_client()

        result = await client.verify_key("unkey_live_abc")

        assert result.rate_limited is True
        assert result.valid is False

    @pytest.mark.asyncio
    @respx.mock
    async def test_sends_bearer_auth_and_key_body(self):
        route = respx.post("https://api.unkey.com/v2/keys.verifyKey").mock(
            return_value=httpx.Response(200, json={"meta": {}, "data": {"valid": True, "code": "VALID"}})
        )
        client = make_client(root_key="root_xyz")

        await client.verify_key("the_key_to_check")

        request = route.calls.last.request
        assert request.headers["Authorization"] == "Bearer root_xyz"
        assert json.loads(request.content) == {"key": "the_key_to_check"}

    @pytest.mark.asyncio
    @respx.mock
    async def test_server_error_raises_unkey_error(self):
        respx.post("https://api.unkey.com/v2/keys.verifyKey").mock(
            return_value=httpx.Response(500, text="internal error")
        )
        client = make_client()

        with pytest.raises(UnkeyError):
            await client.verify_key("some_key")

    @pytest.mark.asyncio
    @respx.mock
    async def test_network_failure_raises_unkey_error(self):
        respx.post("https://api.unkey.com/v2/keys.verifyKey").mock(
            side_effect=httpx.ConnectError("connection refused")
        )
        client = make_client()

        with pytest.raises(UnkeyError):
            await client.verify_key("some_key")

    @pytest.mark.asyncio
    @respx.mock
    async def test_malformed_response_raises_unkey_error(self):
        respx.post("https://api.unkey.com/v2/keys.verifyKey").mock(
            return_value=httpx.Response(200, json={"unexpected": "shape"})
        )
        client = make_client()

        with pytest.raises(UnkeyError):
            await client.verify_key("some_key")


class TestTenantId:
    """tenant_id extraction - see VerifyKeyResult.tenant_id's docstring for the priority order."""

    @pytest.mark.asyncio
    @respx.mock
    async def test_tenant_id_from_identity_external_id(self):
        respx.post("https://api.unkey.com/v2/keys.verifyKey").mock(
            return_value=httpx.Response(
                200,
                json={
                    "meta": {},
                    "data": {
                        "valid": True, "code": "VALID", "keyId": "key_123",
                        "identity": {"id": "id_1", "externalId": "tenant-abc", "meta": {}},
                    },
                },
            )
        )
        result = await make_client().verify_key("unkey_live_abc")

        assert result.tenant_id == "tenant-abc"

    @pytest.mark.asyncio
    @respx.mock
    async def test_explicit_key_meta_tenant_id_overrides_identity_external_id(self):
        respx.post("https://api.unkey.com/v2/keys.verifyKey").mock(
            return_value=httpx.Response(
                200,
                json={
                    "meta": {},
                    "data": {
                        "valid": True, "code": "VALID", "keyId": "key_123",
                        "meta": {"tenant_id": "tenant-from-key-meta"},
                        "identity": {"id": "id_1", "externalId": "tenant-from-identity", "meta": {}},
                    },
                },
            )
        )
        result = await make_client().verify_key("unkey_live_abc")

        assert result.tenant_id == "tenant-from-key-meta"

    @pytest.mark.asyncio
    @respx.mock
    async def test_no_identity_or_meta_gives_no_tenant_id(self):
        respx.post("https://api.unkey.com/v2/keys.verifyKey").mock(
            return_value=httpx.Response(
                200,
                json={"meta": {}, "data": {"valid": True, "code": "VALID", "keyId": "key_123"}},
            )
        )
        result = await make_client().verify_key("unkey_live_abc")

        assert result.tenant_id is None

    @pytest.mark.asyncio
    @respx.mock
    async def test_identity_present_but_no_external_id_gives_no_tenant_id(self):
        respx.post("https://api.unkey.com/v2/keys.verifyKey").mock(
            return_value=httpx.Response(
                200,
                json={
                    "meta": {},
                    "data": {
                        "valid": True, "code": "VALID", "keyId": "key_123",
                        "identity": {"id": "id_1", "meta": {}},
                    },
                },
            )
        )
        result = await make_client().verify_key("unkey_live_abc")

        assert result.tenant_id is None
