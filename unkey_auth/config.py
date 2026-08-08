import os
from pydantic import BaseModel, Field


class Config(BaseModel):
    """Configuration for the unkey-auth library."""

    # Unkey API
    unkey_base_url: str = Field(default_factory=lambda: os.getenv("UNKEY_BASE_URL", "https://api.unkey.com/v2"))
    unkey_root_key: str = Field(default_factory=lambda: os.getenv("UNKEY_ROOT_KEY", ""))
    unkey_api_id: str = Field(default_factory=lambda: os.getenv("UNKEY_API_ID", ""))

    # HTTP behavior
    verify_timeout_seconds: float = Field(default=5.0)

    @property
    def enabled(self) -> bool:
        """Whether real key verification can run at all.

        No root key means this deployment hasn't been given real Unkey
        credentials yet - callers should fail open rather than reject every
        request against an API they can't actually reach.
        """
        return bool(self.unkey_root_key)

    @classmethod
    def from_env(cls) -> "Config":
        return cls()
