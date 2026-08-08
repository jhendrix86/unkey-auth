from typing import Any, Dict, List, Optional

import httpx
from pydantic import BaseModel, Field

from .config import Config


class VerifyKeyResult(BaseModel):
    """Parsed result of a keys.verifyKey call."""

    valid: bool
    code: str
    key_id: Optional[str] = None
    ratelimits: List[Dict[str, Any]] = Field(default_factory=list)
    raw: Dict[str, Any] = Field(default_factory=dict)

    @property
    def rate_limited(self) -> bool:
        return self.code == "RATE_LIMITED"


class UnkeyError(Exception):
    """Raised when the Unkey API can't be reached or returns an unexpected shape."""


class UnkeyClient:
    """Thin async client around Unkey's v2 key-verification API.

    https://api.unkey.com/v2/keys.verifyKey - POST, Authorization: Bearer <root key>,
    body {"key": "<key to verify>"}. Rate limits configured on the key in the
    Unkey dashboard are evaluated as part of this same call (code == "RATE_LIMITED"
    when exceeded) - there is no separate rate-limit call for the common case.
    """

    def __init__(self, config: Optional[Config] = None):
        self.config = config or Config.from_env()

    async def verify_key(self, key: str) -> VerifyKeyResult:
        if not self.config.enabled:
            raise UnkeyError("UNKEY_ROOT_KEY is not configured")

        url = f"{self.config.unkey_base_url}/keys.verifyKey"
        headers = {
            "Authorization": f"Bearer {self.config.unkey_root_key}",
            "Content-Type": "application/json",
        }

        try:
            async with httpx.AsyncClient(timeout=self.config.verify_timeout_seconds) as client:
                response = await client.post(url, headers=headers, json={"key": key})
        except httpx.HTTPError as exc:
            raise UnkeyError(f"Unkey API request failed: {exc}") from exc

        if response.status_code >= 500:
            raise UnkeyError(f"Unkey API returned {response.status_code}")

        try:
            body = response.json()
            data = body["data"]
        except (ValueError, KeyError) as exc:
            raise UnkeyError(f"Unexpected Unkey response shape: {response.text[:200]}") from exc

        return VerifyKeyResult(
            valid=bool(data.get("valid", False)),
            code=data.get("code", "UNKNOWN"),
            key_id=data.get("keyId"),
            ratelimits=data.get("ratelimits", []) or [],
            raw=data,
        )
