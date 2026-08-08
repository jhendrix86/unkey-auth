# unkey-auth

Shared Unkey (unkey.com) API key verification and rate-limiting client for the
OS42 engine fleet. Wraps `POST /v2/keys.verifyKey` and exposes a FastAPI
dependency, `require_api_key`, that engines add to routes they want gated.

## Setup

Each engine depends on this as a local editable install, matching the
`autonomy-events` convention:

```
-e ../unkey-auth
```

in the engine's `requirements.txt`.

## Configuration

- `UNKEY_ROOT_KEY` - your Unkey workspace root key. **Required for real
  enforcement.** If unset, `require_api_key` fails open (logs a warning once,
  allows every request through unverified) so engines can adopt the
  dependency before a real Unkey workspace exists.
- `UNKEY_API_ID` - the Unkey API namespace, if you need it for key creation
  elsewhere (not used by `require_api_key` itself).
- `UNKEY_BASE_URL` - defaults to `https://api.unkey.com/v2`.

## Usage

```python
from fastapi import Depends
from unkey_auth import require_api_key

@router.get("/", dependencies=[Depends(require_api_key)])
async def list_things():
    ...
```

Once `UNKEY_ROOT_KEY` is set, requests without a valid `Authorization: Bearer
<key>` header get `401`, rate-limited keys get `429`, and an unreachable
Unkey API gets `503` (fails closed once enabled - an auth gate that silently
no-ops on infra trouble isn't a gate).
