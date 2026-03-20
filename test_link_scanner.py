from datetime import datetime, timezone
import unittest
from unittest.mock import patch

from actions import _reset_alert_cache, handle_review
from config import Settings, set_settings_store
from discord_invite_checker import InviteInfo
from link_scanner import ResolvedUrl, ScanResult, UrlCandidate, extract_invites, extract_urls_for_scanning, resolve_url
from mongo_store import InMemorySettingsStore
from risk_engine import _reset_recent_suspicious_events, evaluate_message_scan


class ExtractInvitesTests(unittest.TestCase):
    def test_plain_invite(self) -> None:
        result = extract_invites("join here https://discord.gg/abc123")
        self.assertEqual(result["invites"], ["https://discord.gg/abc123"])
        self.assertFalse(result["obfuscated"])

    def test_percent_encoded_payload(self) -> None:
        result = extract_invites(
            "discord:/#/@%64%69%73%63%6F%72%64%2E%67%67/%61%62%63%31%32%33"
        )
        self.assertEqual(result["invites"], ["https://discord.gg/abc123"])
        self.assertTrue(result["obfuscated"])
        self.assertIn("percent_decoding", result["signals"])

    def test_split_camouflaged_payload(self) -> None:
        result = extract_invites(
            "<dI\ns\nCo\nrd:/#\n@%64%69%73%63%6F%72%64%2E%67%67/%61%62%63%31%32%33>"
        )
        self.assertEqual(result["invites"], ["https://discord.gg/abc123"])
        self.assertTrue(result["obfuscated"])
        self.assertIn("percent_decoding", result["signals"])
        self.assertIn("whitespace_flattening", result["signals"])

    def test_embedded_invite_in_junk(self) -> None:
        result = extract_invites("xxxdiscord.gg/abc123yyy")
        self.assertEqual(result["invites"], ["https://discord.gg/abc123yyy"])
        self.assertIn("embedded_invite", result["signals"])

    def test_harmless_text(self) -> None:
        result = extract_invites("hello world")
        self.assertEqual(result["invites"], [])
        self.assertFalse(result["obfuscated"])
        self.assertEqual(result["signals"], [])

    def test_discord_wrapper_payload(self) -> None:
        text = (
            "<dI\n"
            "s\n"
            "Co\n"
            "rd:/#\n"
            "@%\n"
            "64%69%73%63%6F%72%64%2E%67%67/%76%53%39%37%38%71%79%76%4B%74>"
        )
        result = extract_invites(text)
        self.assertEqual(result["invites"], ["https://discord.gg/vS978qyvKt"])
        self.assertTrue(result["obfuscated"])
        self.assertIn("percent_decoding", result["signals"])
        self.assertIn("whitespace_flattening", result["signals"])

    def test_mailto_wrapper_payload(self) -> None:
        text = (
            "<mai\n"
            "L\n"
            "To\n"
            ":////#@%\n"
            "64\n"
            "%\n"
            "69%73%\n"
            "63\n"
            "%6F%72%64%2\n"
            "e%67%67/vS978qyvKt>"
        )
        result = extract_invites(text)
        self.assertEqual(result["invites"], ["https://discord.gg/vS978qyvKt"])
        self.assertTrue(result["obfuscated"])
        self.assertIn("percent_decoding", result["signals"])
        self.assertIn("whitespace_flattening", result["signals"])

    def test_quoted_mailto_wrapper_payload(self) -> None:
        text = (
            "_\n"
            "**:link:\u201cFor any enquiry {head} to t!cket Here:arrow_down:\n"
            "> \n"
            ">     <mai\n"
            "> L\n"
            "> To\n"
            "> :////#@%\n"
            "> 64\n"
            "> %\n"
            "> 69%73%\n"
            "> 63\n"
            "> %6F%72%64%2\n"
            "> e%67%67/vS978qyvKt> **"
        )
        result = extract_invites(text)
        self.assertEqual(result["invites"], ["https://discord.gg/vS978qyvKt"])
        self.assertTrue(result["obfuscated"])
        self.assertIn("percent_decoding", result["signals"])
        self.assertIn("whitespace_flattening", result["signals"])
        self.assertIn("markdown_quote_stripping", result["signals"])
        self.assertIn("decoration_stripping", result["signals"])


class ExtractUrlsTests(unittest.TestCase):
    def test_split_obfuscated_bugreport_pages_dev(self) -> None:
        text = "><\nht\ntp\n://bug\nrep\nort\n.pages.dev\\>>"
        result = extract_urls_for_scanning(text)

        self.assertEqual([candidate.url for candidate in result["urls"]], ["http://bugreport.pages.dev"])
        self.assertIn("url_found", result["signals"])
        self.assertIn("obfuscated_url", result["signals"])
        self.assertIn("whitespace_flattening", result["signals"])

    def test_unicode_dot_normalization(self) -> None:
        text = "http://bugreport\u3002pages\u3002dev"
        result = extract_urls_for_scanning(text)

        self.assertEqual([candidate.url for candidate in result["urls"]], ["http://bugreport.pages.dev"])
        self.assertIn("unicode_dot_normalization", result["signals"])

    def test_harmless_normal_url(self) -> None:
        result = extract_urls_for_scanning("visit https://example.com/docs")

        self.assertEqual([candidate.url for candidate in result["urls"]], ["https://example.com/docs"])
        self.assertIn("url_found", result["signals"])
        self.assertNotIn("obfuscated_url", result["signals"])


class ResolveUrlTests(unittest.IsolatedAsyncioTestCase):
    async def test_redirect_to_discord_invite(self) -> None:
        session = FakeSession(
            {
                ("HEAD", "http://bugreport.pages.dev"): FakeResponse(
                    url="https://discord.gg/abc123",
                    status=200,
                    history=("redirect",),
                ),
            }
        )

        result = await resolve_url(
            UrlCandidate(url="http://bugreport.pages.dev", signals=("url_found", "obfuscated_url")),
            session,
        )

        self.assertTrue(result.resolved)
        self.assertTrue(result.redirected)
        self.assertEqual(result.final_url, "https://discord.gg/abc123")
        self.assertEqual(result.final_domain, "discord.gg")
        self.assertEqual(result.final_invite_url, "https://discord.gg/abc123")
        self.assertIn("redirect_followed", result.signals)

    async def test_head_falls_back_to_get(self) -> None:
        session = FakeSession(
            {
                ("HEAD", "http://bugreport.pages.dev"): FakeResponse(
                    url="http://bugreport.pages.dev",
                    status=405,
                    history=(),
                ),
                ("GET", "http://bugreport.pages.dev"): FakeResponse(
                    url="https://example.com/landing",
                    status=200,
                    history=("redirect",),
                ),
            }
        )

        result = await resolve_url("http://bugreport.pages.dev", session)

        self.assertTrue(result.resolved)
        self.assertEqual(result.final_url, "https://example.com/landing")
        self.assertIn(("HEAD", "http://bugreport.pages.dev"), session.calls)
        self.assertIn(("GET", "http://bugreport.pages.dev"), session.calls)

    async def test_html_meta_refresh_to_discord_invite(self) -> None:
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
                        b'<html><head><meta http-equiv="refresh" '
                        b'content="0; url=https://discord.gg/abc123"></head></html>'
                    ),
                ),
            }
        )

        result = await resolve_url("http://bugreport.pages.dev", session)

        self.assertTrue(result.resolved)
        self.assertTrue(result.html_redirect_detected)
        self.assertEqual(result.final_url, "https://discord.gg/abc123")
        self.assertEqual(result.final_invite_url, "https://discord.gg/abc123")
        self.assertIn("html_redirect_detected", result.signals)
        self.assertIn("meta_refresh_redirect", result.signals)

    async def test_html_javascript_redirect_to_discord_invite(self) -> None:
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
                    body=b'<script>window.location.href="https://discord.gg/abc123"</script>',
                ),
            }
        )

        result = await resolve_url("http://bugreport.pages.dev", session)

        self.assertTrue(result.resolved)
        self.assertTrue(result.html_redirect_detected)
        self.assertEqual(result.final_url, "https://discord.gg/abc123")
        self.assertEqual(result.final_invite_url, "https://discord.gg/abc123")
        self.assertIn("javascript_redirect", result.signals)
        self.assertIn("javascript_redirect_detected", result.signals)

    async def test_html_base64_javascript_interstitial_redirect_to_discord_invite(self) -> None:
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
                        b"<!DOCTYPE html>"
                        b"<html>"
                        b"<head><meta charset=\"UTF-8\"><title>Please wait...</title></head>"
                        b"<body>"
                        b"<p>Loading secure page...</p>"
                        b"<script>"
                        b"(function(){var d=atob(\"aHR0cHM6Ly9kaXNjb3JkLmdnL3ZTOTc4cXl2S3Q=\");"
                        b"setTimeout(function(){window.location.href=d},500)})();"
                        b"</script>"
                        b"</body>"
                        b"</html>"
                    ),
                ),
            }
        )

        result = await resolve_url("http://bugreport.pages.dev", session)

        self.assertTrue(result.resolved)
        self.assertTrue(result.html_redirect_detected)
        self.assertTrue(result.suspicious_interstitial)
        self.assertEqual(result.final_url, "https://discord.gg/vS978qyvKt")
        self.assertEqual(result.final_invite_url, "https://discord.gg/vS978qyvKt")
        self.assertEqual(result.embedded_invites, ("https://discord.gg/vS978qyvKt",))
        self.assertIn("javascript_redirect", result.signals)
        self.assertIn("javascript_redirect_detected", result.signals)
        self.assertIn("base64_payload_detected", result.signals)
        self.assertIn("decoded_destination", result.signals)
        self.assertIn("delayed_javascript_redirect", result.signals)
        self.assertIn("suspicious_interstitial", result.signals)

    async def test_html_embedded_percent_encoded_invite_is_found(self) -> None:
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
                        b"<html><body>payload "
                        b"%64%69%73%63%6F%72%64%2E%67%67/%61%62%63%31%32%33"
                        b"</body></html>"
                    ),
                ),
            }
        )

        result = await resolve_url("http://bugreport.pages.dev", session)

        self.assertTrue(result.resolved)
        self.assertEqual(result.final_invite_url, "https://discord.gg/abc123")
        self.assertEqual(result.embedded_invites, ("https://discord.gg/abc123",))
        self.assertFalse(result.html_redirect_detected)

    async def test_interstitial_loading_page_is_flagged(self) -> None:
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
                        b"<script>window.location.replace('https://discord.gg/abc123')</script>"
                        b"</body></html>"
                    ),
                ),
            }
        )

        result = await resolve_url("http://bugreport.pages.dev", session)

        self.assertTrue(result.resolved)
        self.assertTrue(result.suspicious_interstitial)
        self.assertTrue(result.html_redirect_detected)
        self.assertEqual(result.final_invite_url, "https://discord.gg/abc123")
        self.assertIn("suspicious_interstitial", result.signals)

    async def test_delayed_javascript_interstitial_redirect_is_found(self) -> None:
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

        result = await resolve_url("http://bugreport.pages.dev", session)

        self.assertTrue(result.resolved)
        self.assertTrue(result.html_redirect_detected)
        self.assertTrue(result.suspicious_interstitial)
        self.assertEqual(result.final_invite_url, "https://discord.gg/abc123")
        self.assertIn("delayed_javascript_redirect", result.signals)

    async def test_harmless_html_atob_usage_is_not_treated_as_redirect(self) -> None:
        session = FakeSession(
            {
                ("HEAD", "https://example.com/docs"): FakeResponse(
                    url="https://example.com/docs",
                    status=200,
                    history=(),
                    content_type="text/html",
                ),
                ("GET", "https://example.com/docs"): FakeResponse(
                    url="https://example.com/docs",
                    status=200,
                    history=(),
                    content_type="text/html",
                    body=(
                        b"<html><body>"
                        b"<script>const text = atob('SGVsbG8gd29ybGQ='); console.log(text);</script>"
                        b"<p>Reference docs</p>"
                        b"</body></html>"
                    ),
                ),
            }
        )

        result = await resolve_url("https://example.com/docs", session)

        self.assertTrue(result.resolved)
        self.assertFalse(result.html_redirect_detected)
        self.assertFalse(result.suspicious_interstitial)
        self.assertEqual(result.final_url, "https://example.com/docs")
        self.assertIsNone(result.final_invite_url)
        self.assertEqual(result.embedded_invites, ())
        self.assertNotIn("decoded_destination", result.signals)

    async def test_harmless_html_page_has_no_malicious_destination(self) -> None:
        session = FakeSession(
            {
                ("HEAD", "https://example.com/docs"): FakeResponse(
                    url="https://example.com/docs",
                    status=200,
                    history=(),
                    content_type="text/html",
                ),
                ("GET", "https://example.com/docs"): FakeResponse(
                    url="https://example.com/docs",
                    status=200,
                    history=(),
                    content_type="text/html",
                    body=b"<html><body>Hello world</body></html>",
                ),
            }
        )

        result = await resolve_url("https://example.com/docs", session)

        self.assertTrue(result.resolved)
        self.assertFalse(result.html_redirect_detected)
        self.assertFalse(result.suspicious_interstitial)
        self.assertIsNone(result.final_invite_url)
        self.assertEqual(result.embedded_invites, ())


class RiskEngineRedirectTests(unittest.TestCase):
    def setUp(self) -> None:
        set_settings_store(InMemorySettingsStore())
        _reset_recent_suspicious_events()

    def test_redirect_to_discord_invite_is_blocked(self) -> None:
        scan_result = ScanResult(
            raw_content="http://bugreport.pages.dev",
            urls=[
                ResolvedUrl(
                    original_url="http://bugreport.pages.dev",
                    normalized_url="http://bugreport.pages.dev",
                    final_url="https://discord.gg/abc123",
                    original_domain="bugreport.pages.dev",
                    final_domain="discord.gg",
                    resolved=True,
                    signals=("url_found", "obfuscated_url", "redirect_followed"),
                    redirected=True,
                    final_invite_url="https://discord.gg/abc123",
                    suspicious_redirector=True,
                    status_code=200,
                    error=None,
                )
            ],
            invites=[],
            redirect_invites=[],
            url_detection={"signals": ["url_found", "obfuscated_url"]},
            invite_detection={},
            obfuscated_invites=False,
        )

        verdict = evaluate_message_scan(scan_result, _build_settings())

        self.assertEqual(verdict.verdict, "block")
        self.assertIn("URL redirected to a Discord invite", verdict.reasons)

    def test_blocked_redirected_invite_server_is_blocked(self) -> None:
        scan_result = ScanResult(
            raw_content="http://bugreport.pages.dev",
            urls=[
                ResolvedUrl(
                    original_url="http://bugreport.pages.dev",
                    normalized_url="http://bugreport.pages.dev",
                    final_url="https://discord.gg/abc123",
                    original_domain="bugreport.pages.dev",
                    final_domain="discord.gg",
                    resolved=True,
                    signals=("url_found", "obfuscated_url", "redirect_followed"),
                    redirected=True,
                    final_invite_url="https://discord.gg/abc123",
                    suspicious_redirector=True,
                    status_code=200,
                    error=None,
                )
            ],
            invites=[],
            redirect_invites=[
                InviteInfo(
                    code="abc123",
                    url="https://discord.gg/abc123",
                    guild_id=42,
                    guild_name="blocked",
                    guild_description=None,
                    approximate_member_count=None,
                    approximate_presence_count=None,
                    channel_id=None,
                    channel_name=None,
                    inviter_id=None,
                    resolved=True,
                    error=None,
                )
            ],
            url_detection={"signals": ["url_found", "obfuscated_url"]},
            invite_detection={},
            obfuscated_invites=False,
        )

        settings = _build_settings(blocked_server_ids={42})
        verdict = evaluate_message_scan(scan_result, settings)

        self.assertEqual(verdict.verdict, "block")
        self.assertEqual(verdict.matched_server_ids, [42])

    def test_unresolved_suspicious_redirector_is_reviewed(self) -> None:
        scan_result = ScanResult(
            raw_content="http://bugreport.pages.dev",
            urls=[
                ResolvedUrl(
                    original_url="http://bugreport.pages.dev",
                    normalized_url="http://bugreport.pages.dev",
                    final_url=None,
                    original_domain="bugreport.pages.dev",
                    final_domain=None,
                    resolved=False,
                    signals=("url_found", "obfuscated_url"),
                    redirected=False,
                    final_invite_url=None,
                    suspicious_redirector=True,
                    status_code=None,
                    error="timeout",
                )
            ],
            invites=[],
            redirect_invites=[],
            url_detection={"signals": ["url_found", "obfuscated_url"]},
            invite_detection={},
            obfuscated_invites=False,
        )

        verdict = evaluate_message_scan(scan_result, _build_settings())

        self.assertEqual(verdict.verdict, "review_high")
        self.assertIn("suspicious redirector URL could not be resolved safely", verdict.reasons)

    def test_unresolved_html_interstitial_is_reviewed(self) -> None:
        scan_result = ScanResult(
            raw_content="http://bugreport.pages.dev",
            urls=[
                ResolvedUrl(
                    original_url="http://bugreport.pages.dev",
                    normalized_url="http://bugreport.pages.dev",
                    final_url="http://bugreport.pages.dev",
                    original_domain="bugreport.pages.dev",
                    final_domain="bugreport.pages.dev",
                    resolved=True,
                    signals=("url_found", "html_redirect_detected", "suspicious_interstitial"),
                    redirected=False,
                    html_redirect_detected=True,
                    final_invite_url=None,
                    embedded_invites=(),
                    suspicious_redirector=True,
                    suspicious_interstitial=True,
                    status_code=200,
                    error=None,
                )
            ],
            invites=[],
            redirect_invites=[],
            url_detection={"signals": ["url_found", "obfuscated_url"]},
            invite_detection={},
            obfuscated_invites=False,
        )

        verdict = evaluate_message_scan(scan_result, _build_settings(allowed_domains={"pages.dev"}))

        self.assertEqual(verdict.verdict, "block")
        self.assertIn("suspicious redirector HTML interstitial detected", verdict.reasons)

    def test_suspicious_redirector_html_interstitial_is_blocked(self) -> None:
        scan_result = ScanResult(
            raw_content="http://bugreport.pages.dev",
            urls=[
                ResolvedUrl(
                    original_url="http://bugreport.pages.dev",
                    normalized_url="http://bugreport.pages.dev",
                    final_url="http://bugreport.pages.dev",
                    original_domain="bugreport.pages.dev",
                    final_domain="bugreport.pages.dev",
                    resolved=True,
                    signals=("url_found", "html_redirect_detected", "suspicious_interstitial"),
                    redirected=False,
                    html_redirect_detected=True,
                    final_invite_url=None,
                    embedded_invites=(),
                    suspicious_redirector=True,
                    suspicious_interstitial=True,
                    status_code=200,
                    error=None,
                )
            ],
            invites=[],
            redirect_invites=[],
            url_detection={"signals": ["url_found", "obfuscated_url"]},
            invite_detection={},
            obfuscated_invites=False,
        )

        verdict = evaluate_message_scan(scan_result, _build_settings())

        self.assertEqual(verdict.verdict, "block")
        self.assertIn("suspicious redirector HTML interstitial detected", verdict.reasons)

    def test_unknown_clean_external_link_is_low_priority_review(self) -> None:
        scan_result = ScanResult(
            raw_content="https://example.com/docs",
            urls=[
                ResolvedUrl(
                    original_url="https://example.com/docs",
                    normalized_url="https://example.com/docs",
                    final_url="https://example.com/docs",
                    original_domain="example.com",
                    final_domain="example.com",
                    resolved=True,
                    signals=("url_found",),
                    redirected=False,
                    final_invite_url=None,
                    suspicious_redirector=False,
                    status_code=200,
                    error=None,
                )
            ],
            invites=[],
            redirect_invites=[],
            url_detection={"signals": ["url_found"]},
            invite_detection={"signals": []},
            obfuscated_invites=False,
        )

        verdict = evaluate_message_scan(scan_result, _build_settings())

        self.assertEqual(verdict.verdict, "review_low")
        self.assertEqual(verdict.alert_level, "quiet")
        self.assertLess(verdict.score, 50)

    def test_obfuscated_hidden_invite_is_high_priority_review(self) -> None:
        scan_result = ScanResult(
            raw_content="ticket support <maiLTo:////#@%64%69%73%63%6F%72%64%2E%67%67/vS978qyvKt>",
            urls=[],
            invites=[
                InviteInfo(
                    code="vS978qyvKt",
                    url="https://discord.gg/vS978qyvKt",
                    guild_id=7,
                    guild_name="unknown",
                    guild_description=None,
                    approximate_member_count=None,
                    approximate_presence_count=None,
                    channel_id=None,
                    channel_name=None,
                    inviter_id=None,
                    resolved=True,
                    error=None,
                )
            ],
            redirect_invites=[],
            url_detection={"signals": []},
            invite_detection={"signals": ["percent_decoding", "embedded_invite", "whitespace_flattening"]},
            obfuscated_invites=True,
        )

        verdict = evaluate_message_scan(scan_result, _build_settings())

        self.assertEqual(verdict.verdict, "review_high")
        self.assertEqual(verdict.alert_level, "main")
        self.assertGreaterEqual(verdict.score, 50)

    def test_blocked_domain_is_blocked(self) -> None:
        scan_result = _build_unknown_url_scan_result()

        verdict = evaluate_message_scan(scan_result, _build_settings(blocked_domains={"example.com"}))

        self.assertEqual(verdict.verdict, "block")
        self.assertIn("matched blocked domain", verdict.reasons)

    def test_repeated_low_confidence_events_gain_extra_score(self) -> None:
        scan_result = ScanResult(
            raw_content="https://example.com/docs",
            urls=[
                ResolvedUrl(
                    original_url="https://example.com/docs",
                    normalized_url="https://example.com/docs",
                    final_url="https://example.com/docs",
                    original_domain="example.com",
                    final_domain="example.com",
                    resolved=True,
                    signals=("url_found",),
                    redirected=False,
                    final_invite_url=None,
                    suspicious_redirector=False,
                    status_code=200,
                    error=None,
                )
            ],
            invites=[],
            redirect_invites=[],
            url_detection={"signals": ["url_found"]},
            invite_detection={"signals": []},
            obfuscated_invites=False,
        )

        verdict_one = evaluate_message_scan(scan_result, _build_settings(), user_id=123)
        verdict_two = evaluate_message_scan(scan_result, _build_settings(), user_id=123)
        verdict_three = evaluate_message_scan(scan_result, _build_settings(), user_id=123)

        self.assertEqual(verdict_one.verdict, "review_low")
        self.assertEqual(verdict_two.verdict, "review_low")
        self.assertEqual(verdict_three.verdict, "review_low")
        self.assertGreater(verdict_three.score, verdict_one.score)
        self.assertIn("repeated suspicious activity from the same user", verdict_three.reasons)


class ActionAlertTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self) -> None:
        set_settings_store(InMemorySettingsStore())
        _reset_alert_cache()

    async def test_low_priority_review_is_quiet_logged_only(self) -> None:
        verdict = evaluate_message_scan(_build_unknown_url_scan_result(), _build_settings())
        message = FakeMessage(content="https://example.com/docs")

        with patch("actions.quiet_review_logger.info") as quiet_log:
            await handle_review(message, verdict, _build_settings(mod_log_channel_id=999))

        self.assertEqual(len(message.guild._channel.sent_embeds), 0)
        quiet_log.assert_called_once()

    async def test_repeated_identical_low_priority_reviews_are_deduplicated(self) -> None:
        verdict = evaluate_message_scan(_build_unknown_url_scan_result(), _build_settings())
        first = FakeMessage(content="https://example.com/docs")
        second = FakeMessage(content="https://example.com/docs")

        with patch("actions.quiet_review_logger.info") as quiet_log:
            await handle_review(first, verdict, _build_settings(mod_log_channel_id=999))
            await handle_review(second, verdict, _build_settings(mod_log_channel_id=999))

        self.assertEqual(quiet_log.call_count, 1)
        self.assertEqual(len(first.guild._channel.sent_embeds), 0)
        self.assertEqual(len(second.guild._channel.sent_embeds), 0)

    async def test_repeated_high_priority_reviews_are_summarized_after_cooldown(self) -> None:
        verdict = evaluate_message_scan(_build_pages_dev_interstitial_scan_result(), _build_settings(allowed_domains={"pages.dev"}))
        shared_channel = FakeChannel()
        first = FakeMessage(content="http://bugreport.pages.dev", user_id=100, channel=shared_channel)
        second = FakeMessage(content="http://bugreport.pages.dev", user_id=101, channel=shared_channel)
        third = FakeMessage(content="http://bugreport.pages.dev", user_id=102, channel=shared_channel)

        with patch("actions.time.monotonic", side_effect=[1.0, 60.0, 360.0]):
            await handle_review(first, verdict, _build_settings(mod_log_channel_id=999))
            await handle_review(second, verdict, _build_settings(mod_log_channel_id=999))
            await handle_review(third, verdict, _build_settings(mod_log_channel_id=999))

        sent_embeds = shared_channel.sent_embeds
        self.assertEqual(len(sent_embeds), 2)
        recent_activity = next(
            field.value for field in sent_embeds[1].fields if field.name == "Recent Activity"
        )
        self.assertIn("Suppressed 1 similar events", recent_activity)
        self.assertIn("3 user(s)", recent_activity)


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
    def __init__(self, response: FakeResponse | Exception) -> None:
        self.response = response

    async def __aenter__(self):
        if isinstance(self.response, Exception):
            raise self.response
        return await self.response.__aenter__()

    async def __aexit__(self, exc_type, exc, tb):
        if isinstance(self.response, Exception):
            return False
        return await self.response.__aexit__(exc_type, exc, tb)


class FakeSession:
    def __init__(self, responses: dict[tuple[str, str], FakeResponse | Exception]) -> None:
        self.responses = responses
        self.calls: list[tuple[str, str]] = []

    def head(self, url: str, **kwargs):
        self.calls.append(("HEAD", url))
        return FakeRequest(self.responses[("HEAD", url)])

    def get(self, url: str, **kwargs):
        self.calls.append(("GET", url))
        return FakeRequest(self.responses[("GET", url)])


def _build_settings(
    *,
    blocked_server_ids: set[int] | None = None,
    allowed_server_ids: set[int] | None = None,
    blocked_domains: set[str] | None = None,
    allowed_domains: set[str] | None = None,
    mod_log_channel_id: int | None = None,
) -> Settings:
    return Settings(
        discord_bot_token="token",
        mod_log_channel_id=mod_log_channel_id,
        block_punishment="none",
        appeal_form_url=None,
        action_timeout_minutes=10,
        http_timeout_seconds=10,
        log_level="INFO",
        blocked_server_ids=blocked_server_ids or set(),
        allowed_server_ids=allowed_server_ids or set(),
        blocked_domains=blocked_domains or set(),
        allowed_domains=allowed_domains or set(),
    )


def _build_unknown_url_scan_result() -> ScanResult:
    return ScanResult(
        raw_content="https://example.com/docs",
        urls=[
            ResolvedUrl(
                original_url="https://example.com/docs",
                normalized_url="https://example.com/docs",
                final_url="https://example.com/docs",
                original_domain="example.com",
                final_domain="example.com",
                resolved=True,
                signals=("url_found",),
                redirected=False,
                final_invite_url=None,
                suspicious_redirector=False,
                status_code=200,
                error=None,
            )
        ],
        invites=[],
        redirect_invites=[],
        url_detection={"signals": ["url_found"]},
        invite_detection={"signals": []},
        obfuscated_invites=False,
    )


def _build_pages_dev_interstitial_scan_result() -> ScanResult:
    return ScanResult(
        raw_content="http://bugreport.pages.dev",
        urls=[
            ResolvedUrl(
                original_url="http://bugreport.pages.dev",
                normalized_url="http://bugreport.pages.dev",
                final_url="http://bugreport.pages.dev",
                original_domain="bugreport.pages.dev",
                final_domain="bugreport.pages.dev",
                resolved=True,
                signals=("url_found", "html_redirect_detected", "suspicious_interstitial"),
                redirected=False,
                html_redirect_detected=True,
                final_invite_url=None,
                embedded_invites=(),
                suspicious_redirector=True,
                suspicious_interstitial=True,
                status_code=200,
                error=None,
            )
        ],
        invites=[],
        redirect_invites=[],
        url_detection={"signals": ["url_found", "obfuscated_url"]},
        invite_detection={"signals": []},
        obfuscated_invites=False,
    )


class FakeChannel:
    def __init__(self, channel_id: int = 999) -> None:
        self.id = channel_id
        self.mention = f"<#{channel_id}>"
        self.sent_embeds = []

    async def send(self, *, embed):
        self.sent_embeds.append(embed)


class FakeGuild:
    def __init__(self, channel: FakeChannel) -> None:
        self._channel = channel

    def get_channel(self, channel_id: int):
        if channel_id == self._channel.id:
            return self._channel
        return None


class FakeAuthor:
    def __init__(self, user_id: int) -> None:
        self.id = user_id
        self.created_at = datetime(2026, 3, 18, tzinfo=timezone.utc)

    def __str__(self) -> str:
        return f"user-{self.id}"


class FakeMessage:
    def __init__(self, *, content: str, user_id: int = 123, channel=None) -> None:
        channel = channel or FakeChannel()
        self.content = content
        self.author = FakeAuthor(user_id)
        self.channel = channel
        self.guild = FakeGuild(channel)
        self.id = user_id


if __name__ == "__main__":
    unittest.main()
