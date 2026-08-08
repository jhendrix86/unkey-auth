import logging
from typing import Optional

from fastapi import Header, HTTPException

from .client import UnkeyClient, UnkeyError, VerifyKeyResult
from .config import Config

logger = logging.getLogger("unkey_auth")

_client: Optional[UnkeyClient] = None
_warned_disabled = False


def get_client() -> UnkeyClient:
    global _client
    if _client is None:
        _client = UnkeyClient(Config.from_env())
    return _client


async def require_api_key(authorization: Optional[str] = Header(default=None)) -> Optional[VerifyKeyResult]:
    """FastAPI dependency that verifies the caller's API key against Unkey.

    Fails OPEN (allows the request, returns None) when UNKEY_ROOT_KEY isn't
    configured, so engines can adopt this dependency before a real Unkey
    workspace exists without breaking every existing route. Once a real root
    key is set, this starts enforcing for real: missing/invalid key -> 401,
    rate-limited key -> 429, Unkey API unreachable -> 503 (fails closed once
    enabled, since an auth gate that silently no-ops on infra trouble isn't
    a gate).
    """
    client = get_client()

    if not client.config.enabled:
        global _warned_disabled
        if not _warned_disabled:
            logger.warning(
                "UNKEY_ROOT_KEY is not set - require_api_key is allowing all requests through unverified. "
                "Set UNKEY_ROOT_KEY to enable real key verification."
            )
            _warned_disabled = True
        return None

    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Missing or malformed Authorization header")

    key = authorization[len("Bearer "):].strip()
    if not key:
        raise HTTPException(status_code=401, detail="Missing API key")

    try:
        result = await client.verify_key(key)
    except UnkeyError as exc:
        logger.error(f"Unkey verification unavailable: {exc}")
        raise HTTPException(status_code=503, detail="Key verification service unavailable") from exc

    if result.rate_limited:
        raise HTTPException(status_code=429, detail="Rate limit exceeded")

    if not result.valid:
        raise HTTPException(status_code=401, detail=f"Invalid API key ({result.code})")

    return result
