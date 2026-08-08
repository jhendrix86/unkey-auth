"""
Regression test for a real bug found in review: engines configure this
library via their own .env file, but pydantic-settings (what every engine's
own Settings class uses) parses .env internally and never exports values
into os.environ - so a plain os.getenv() read here would never see them.
Config must load its own .env via python-dotenv to actually pick this up.
"""
import os

from unkey_auth.config import Config


def test_root_key_is_read_from_a_real_env_file(tmp_path, monkeypatch):
    monkeypatch.delenv("UNKEY_ROOT_KEY", raising=False)
    monkeypatch.chdir(tmp_path)
    (tmp_path / ".env").write_text("UNKEY_ROOT_KEY=key_from_dotenv_file\n")

    config = Config.from_env()

    assert config.unkey_root_key == "key_from_dotenv_file"
    assert config.enabled is True

    # cleanup: load_dotenv() sets process env, which would otherwise leak
    # into later tests run in the same process
    os.environ.pop("UNKEY_ROOT_KEY", None)
