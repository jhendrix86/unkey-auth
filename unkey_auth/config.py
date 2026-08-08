import os
from pydantic import BaseModel, Field

from dotenv import find_dotenv, load_dotenv


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
        # Engines that adopt this library configure it via their own .env
        # file (see README), but pydantic-settings' BaseSettings (used by
        # every engine's own Settings class) parses .env internally and
        # never exports values into os.environ - so plain os.getenv() reads
        # above would never see them without loading the .env file
        # ourselves. load_dotenv() searches the current working directory
        # (and upward) and does not override already-set real environment
        # variables, so this is safe to call every time this is built.
        # usecwd=True is required: without it, find_dotenv() walks up from
        # *this file's own location* (inside the installed unkey-auth
        # package) rather than from the process's actual working directory
        # - which would search the wrong directory entirely for engines
        # that install this as an editable dependency.
        load_dotenv(find_dotenv(usecwd=True))
        return cls()
