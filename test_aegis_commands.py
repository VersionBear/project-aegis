from __future__ import annotations

import unittest
from datetime import datetime, timezone
from types import SimpleNamespace

from aegis_commands import (
    _is_moderator,
    _reset_runtime_state,
    analyze_text,
    build_lists_embed,
    build_scan_embed,
    build_status_embed,
    set_block_punishment,
    set_mod_log_channel,
    update_domain_entry,
    update_server_entry,
    get_enforcement_mode,
    set_enforcement_mode,
)
from config import Settings, set_settings_store
from mongo_store import InMemorySettingsStore


class AegisCommandTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self) -> None:
        set_settings_store(InMemorySettingsStore())
        _reset_runtime_state()

    async def test_scan_plain_discord_invite(self) -> None:
        report = await analyze_text(
            "join https://discord.gg/abc123",
            FakeSession({}),
            FakeClient(),
            _build_settings(),
            user_id=1,
        )

        embed = build_scan_embed(report, "join https://discord.gg/abc123")

        self.assertEqual(embed.title, "Aegis Scan")
        self.assertIn("review_low", embed.fields[0].value)
        self.assertIn("https://discord.gg/abc123", embed.fields[2].value)

    async def test_scan_obfuscated_invite(self) -> None:
        report = await analyze_text(
            "<dI\ns\nCo\nrd:/#\n@%64%69%73%63%6F%72%64%2E%67%67/%61%62%63%31%32%33>",
            FakeSession({}),
            FakeClient(),
            _build_settings(),
            user_id=1,
        )

        embed = build_scan_embed(report, "sample")

        self.assertEqual(report.verdict.verdict, "review_high")
        self.assertIn("percent_decoding", embed.fields[4].value)
        self.assertIn("whitespace_flattening", embed.fields[4].value)

    async def test_scan_redirect_interstitial_sample(self) -> None:
        session = FakeSession(
            {
                ("HEAD", "http://bugreport.pages.dev"): FakeResponse(
                    url="http://bugreport.pages.dev",
                    status=200,
                    history=(),
                    content_type="text/html",
                ),
                ("GET", "http://bugreport.pages.dev"): FakeResponse(
                    url="http://bugreport.pages.dev",
                    status=200,
                    history=(),
                    content_type="text/html",
                    body=(
                        b"<html><body>Loading a secure page"
                        b"<script>setTimeout(function(){window.location.assign('https://discord.gg/abc123')},1500)</script>"
                        b"</body></html>"
                    ),
                ),
            }
        )
        report = await analyze_text(
            "http://bugreport.pages.dev",
            session,
            FakeClient(),
            _build_settings(),
            user_id=1,
        )

        embed = build_scan_embed(report, "http://bugreport.pages.dev")

        self.assertEqual(report.verdict.verdict, "block")
        self.assertIn("html-redirect", embed.fields[3].value)
        self.assertIn("https://discord.gg/abc123", embed.fields[3].value)

    def test_permission_helper_is_mod_only(self) -> None:
        moderator = SimpleNamespace(
            guild_permissions=SimpleNamespace(
                administrator=False,
                manage_guild=False,
                manage_messages=True,
                moderate_members=False,
            )
        )
        regular_user = SimpleNamespace(
            guild_permissions=SimpleNamespace(
                administrator=False,
                manage_guild=False,
                manage_messages=False,
                moderate_members=False,
            )
        )

        self.assertTrue(_is_moderator(moderator))
        self.assertFalse(_is_moderator(regular_user))

    def test_mode_toggle_and_status_report(self) -> None:
        set_enforcement_mode("monitor")
        status = build_status_embed(_build_settings())

        self.assertEqual(get_enforcement_mode(), "monitor")
        self.assertEqual(status.title, "Aegis Status")
        self.assertIn("monitor", status.fields[1].value)

    def test_setup_and_list_management_updates_settings(self) -> None:
        settings = _build_settings()

        channel_id = set_mod_log_channel(settings, 321)
        punishment, timeout_minutes, appeal_url = set_block_punishment(
            settings,
            punishment="kick",
            timeout_minutes=30,
            appeal_form_url="https://appeal.example/form",
        )
        domain = update_domain_entry(settings, "blocklist", "add", "Example.com")
        server_id = update_server_entry(settings, "allowlist", "add", 456)

        self.assertEqual(channel_id, 321)
        self.assertEqual(settings.mod_log_channel_id, 321)
        self.assertEqual(punishment, "kick")
        self.assertEqual(timeout_minutes, 30)
        self.assertEqual(appeal_url, "https://appeal.example/form")
        self.assertEqual(settings.block_punishment, "kick")
        self.assertEqual(settings.action_timeout_minutes, 30)
        self.assertEqual(settings.appeal_form_url, "https://appeal.example/form")
        self.assertEqual(domain, "example.com")
        self.assertIn("example.com", settings.blocked_domains)
        self.assertEqual(server_id, 456)
        self.assertIn(456, settings.allowed_server_ids)
        status = build_status_embed(settings)
        self.assertIn("punishment kick", status.fields[6].value)
        self.assertIn("appeal set", status.fields[6].value)

    def test_lists_embed_shows_domains_and_servers(self) -> None:
        settings = _build_settings()
        settings.allowed_domains.add("example.com")
        settings.blocked_domains.add("bad.example")
        settings.allowed_server_ids.add(123)
        settings.blocked_server_ids.add(456)

        embed = build_lists_embed(settings, "all")

        self.assertEqual(embed.title, "Aegis Lists")
        self.assertIn("example.com", embed.fields[0].value)
        self.assertIn("bad.example", embed.fields[1].value)
        self.assertIn("123", embed.fields[2].value)
        self.assertIn("456", embed.fields[3].value)


class FakeClient:
    def __init__(self) -> None:
        self.user = SimpleNamespace(id=999)

    async def fetch_invite(self, url: str, **kwargs):
        code = url.rsplit("/", 1)[-1]
        return SimpleNamespace(
            guild=SimpleNamespace(id=123, name=f"guild-{code}", description=None),
            channel=SimpleNamespace(id=456, name="general"),
            inviter=SimpleNamespace(id=789),
            approximate_member_count=10,
            approximate_presence_count=5,
        )


class FakeResponse:
    def __init__(
        self,
        url: str,
        status: int,
        history: tuple[object, ...],
        *,
        content_type: str = "application/octet-stream",
        headers: dict[str, str] | None = None,
        body: bytes = b"",
    ) -> None:
        self.url = url
        self.status = status
        self.history = history
        self.content_type = content_type
        self.headers = headers or {"Content-Type": content_type}
        self._body = body

    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc, tb):
        return False

    async def read(self) -> bytes:
        return self._body


class FakeRequest:
    def __init__(self, response: FakeResponse) -> None:
        self.response = response

    async def __aenter__(self):
        return await self.response.__aenter__()

    async def __aexit__(self, exc_type, exc, tb):
        return await self.response.__aexit__(exc_type, exc, tb)


class FakeSession:
    def __init__(self, responses: dict[tuple[str, str], FakeResponse]) -> None:
        self.responses = responses

    def head(self, url: str, **kwargs):
        return FakeRequest(self.responses[("HEAD", url)])

    def get(self, url: str, **kwargs):
        return FakeRequest(self.responses[("GET", url)])


def _build_settings() -> Settings:
    return Settings(
        discord_bot_token="token",
        mod_log_channel_id=None,
        block_punishment="none",
        appeal_form_url=None,
        action_timeout_minutes=10,
        http_timeout_seconds=10,
        log_level="INFO",
        blocked_server_ids=set(),
        allowed_server_ids=set(),
        blocked_domains=set(),
        allowed_domains=set(),
    )


if __name__ == "__main__":
    unittest.main()
