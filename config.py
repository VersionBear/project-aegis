from __future__ import annotations

import os
from dataclasses import dataclass

from dotenv import load_dotenv
from mongo_store import get_default_store


@dataclass(frozen=True)
class Settings:
    discord_bot_token: str
    mod_log_channel_id: int | None
    block_punishment: str
    appeal_form_url: str | None
    action_timeout_minutes: int
    http_timeout_seconds: int
    log_level: str
    blocked_server_ids: set[int]
    allowed_server_ids: set[int]
    blocked_domains: set[str]
    allowed_domains: set[str]


_settings_store = None


def set_settings_store(store) -> None:
    global _settings_store
    _settings_store = store


def _get_settings_store():
    global _settings_store
    if _settings_store is None:
        _settings_store = get_default_store()
    return _settings_store


def _get_int(name: str, default: int | None = None) -> int | None:
    raw_value = os.getenv(name)
    if raw_value is None or raw_value.strip() == "":
        return default
    return int(raw_value)


def save_mod_log_channel_id(channel_id: int | None) -> None:
    runtime_config = _get_settings_store().load_runtime_config()
    runtime_config["mod_log_channel_id"] = channel_id
    _get_settings_store().save_runtime_config(runtime_config)


def save_punishment_settings(*, block_punishment: str, timeout_minutes: int, appeal_form_url: str | None) -> None:
    runtime_config = _get_settings_store().load_runtime_config()
    runtime_config["block_punishment"] = block_punishment
    runtime_config["action_timeout_minutes"] = timeout_minutes
    runtime_config["appeal_form_url"] = appeal_form_url
    _get_settings_store().save_runtime_config(runtime_config)


def save_domain_set(filename: str, values: set[str]) -> None:
    _get_settings_store().save_domain_set(filename, values)


def save_id_set(filename: str, values: set[int]) -> None:
    _get_settings_store().save_id_set(filename, values)


def get_settings() -> Settings:
    load_dotenv()
    runtime_config = _get_settings_store().load_runtime_config()

    discord_bot_token = os.getenv("DISCORD_BOT_TOKEN", "").strip()
    if not discord_bot_token:
        raise RuntimeError("DISCORD_BOT_TOKEN is required")

    return Settings(
        discord_bot_token=discord_bot_token,
        mod_log_channel_id=runtime_config.get("mod_log_channel_id"),
        block_punishment=str(runtime_config.get("block_punishment", "none")),
        appeal_form_url=(
            str(runtime_config.get("appeal_form_url")).strip()
            if runtime_config.get("appeal_form_url")
            else None
        ),
        action_timeout_minutes=int(runtime_config.get("action_timeout_minutes", 10)),
        http_timeout_seconds=_get_int("HTTP_TIMEOUT_SECONDS", 10) or 10,
        log_level=os.getenv("LOG_LEVEL", "INFO").strip().upper() or "INFO",
        blocked_server_ids=_get_settings_store().load_id_set("blocked_servers"),
        allowed_server_ids=_get_settings_store().load_id_set("allowed_servers"),
        blocked_domains=_get_settings_store().load_domain_set("blocked_domains"),
        allowed_domains=_get_settings_store().load_domain_set("allowed_domains"),
    )
