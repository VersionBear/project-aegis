from __future__ import annotations

import base64
import binascii
import logging
import re
import unicodedata
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import unquote, urljoin, urlparse

import aiohttp
import discord

from discord_invite_checker import InviteInfo, inspect_invite
from utils import ParsedInvite, ensure_url_scheme, extract_urls as extract_plain_urls, normalize_domain, parse_invite_url, strip_trailing_punctuation


logger = logging.getLogger("aegis.scanner")

INVITE_CODE_MAX_LENGTH = 64
URL_RESOLUTION_TIMEOUT_SECONDS = 10
URL_RESOLUTION_MAX_REDIRECTS = 5
HTML_INSPECTION_MAX_BYTES = 65536
HTML_LIKE_CONTENT_TYPES = (
    "text/html",
    "application/xhtml+xml",
)
WHITESPACE_RE = re.compile(r"\s+")
LINE_QUOTE_PREFIX_RE = re.compile(r"(?m)^[ \t]*>[ \t]?")
INVITE_MATCH_RE = re.compile(
    r"(?P<domain>discord\.gg|discord\.com/invite|discordapp\.com/invite)/(?P<code>[A-Za-z0-9-]{2,64})",
    re.IGNORECASE,
)
URL_MATCH_RE = re.compile(
    r"(?P<url>https?://(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z]{2,63}(?::\d{1,5})?(?:[/?#][^\s<>\"\']*)?)",
    re.IGNORECASE,
)
PERCENT_SUBSTRING_RE = re.compile(
    r"(?P<blob>%[0-9A-Za-z./:_#@%-]{7,})",
    re.IGNORECASE,
)
META_REFRESH_RE = re.compile(
    r"""<meta\b[^>]*http-equiv\s*=\s*["']?\s*refresh\s*["']?[^>]*content\s*=\s*(?P<quote>["'])(?P<content>.*?)(?P=quote)""",
    re.IGNORECASE | re.DOTALL,
)
META_REFRESH_URL_RE = re.compile(
    r"""url\s*=\s*(?P<target>['"][^'"]+['"]|[^;]+)""",
    re.IGNORECASE,
)
JS_REDIRECT_RE = re.compile(
    r"""
    (?:
        (?:(?:window|document|top|self)\.)?location(?:\.href)?\s*=\s*
        (?P<assign_quote>["'])(?P<assign_target>.+?)(?P=assign_quote)
    )
    |
    (?:
        (?:(?:window|document|top|self)\.)?location\.(?:replace|assign)\(\s*
        (?P<call_quote>["'])(?P<call_target>.+?)(?P=call_quote)\s*\)
    )
    """,
    re.IGNORECASE | re.DOTALL | re.VERBOSE,
)
DELAYED_JS_REDIRECT_RE = re.compile(
    r"""
    (?:setTimeout|setInterval)\s*\(
        (?P<callback>.*?)
    \)
    """,
    re.IGNORECASE | re.DOTALL | re.VERBOSE,
)
INTERSTITIAL_HINT_RE = re.compile(
    r"(loading\s+a\s+secure\s+page|redirecting|please\s+wait|security\s+check|opening\s+discord)",
    re.IGNORECASE,
)
SCRIPT_TAG_RE = re.compile(
    r"<script\b[^>]*>(?P<content>.*?)</script>",
    re.IGNORECASE | re.DOTALL,
)
ATOB_CALL_RE = re.compile(
    r"""atob\(\s*(?P<quote>["'])(?P<payload>[A-Za-z0-9+/=_-]{8,2048})(?P=quote)\s*\)""",
    re.IGNORECASE,
)
JS_VARIABLE_ASSIGNMENT_RE = re.compile(
    r"""\b(?:var|let|const)\s+(?P<name>[A-Za-z_$][\w$]*)\s*=\s*(?P<expr>.+?)(?=;|\n|\r|\}|$)""",
    re.IGNORECASE | re.DOTALL,
)
JS_LOCATION_ASSIGNMENT_RE = re.compile(
    r"""\b(?:(?:window|document|top|self)\.)?location(?:\.href)?\s*=\s*(?!=)\s*(?P<expr>.+?)(?=;|\n|\r|\}|$)""",
    re.IGNORECASE | re.DOTALL,
)
JS_LOCATION_CALL_RE = re.compile(
    r"""\b(?:(?:window|document|top|self)\.)?location\.(?:replace|assign)\(\s*(?P<expr>.+?)\s*\)""",
    re.IGNORECASE | re.DOTALL,
)
JS_IDENTIFIER_RE = re.compile(
    r"^[A-Za-z_$][\w$]*$",
)
BASE64_DECODE_MAX_BYTES = 1536

INVISIBLE_CODEPOINTS = {
    "\u00ad",
    "\u034f",
    "\u061c",
    "\u180e",
    "\u200b",
    "\u200c",
    "\u200d",
    "\u200e",
    "\u200f",
    "\u2060",
    "\u2061",
    "\u2062",
    "\u2063",
    "\u2064",
    "\u2066",
    "\u2067",
    "\u2068",
    "\u2069",
    "\u206a",
    "\u206b",
    "\u206c",
    "\u206d",
    "\u206e",
    "\u206f",
    "\ufeff",
}
PERCENT_SUFFIX_CHARS = set("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789./:_#@-")
DECORATION_TRANSLATION = str.maketrans(
    "",
    "",
    "<>[](){}*_`|\"'\u201c\u201d\u2018\u2019",
)
DOT_VARIANT_TRANSLATION = str.maketrans(
    {
        "\u3002": ".",
        "\uff0e": ".",
        "\uff61": ".",
    }
)
HEAD_FALLBACK_STATUSES = {400, 403, 404, 405, 406, 409, 410, 429, 500, 501, 502, 503, 504}
SUSPICIOUS_REDIRECTOR_DOMAINS = {
    "pages.dev",
    "workers.dev",
    "github.io",
    "netlify.app",
    "vercel.app",
    "web.app",
    "firebaseapp.com",
    "surge.sh",
}


@dataclass(frozen=True)
class ResolvedUrl:
    original_url: str
    normalized_url: str
    final_url: str | None
    original_domain: str | None
    final_domain: str | None
    resolved: bool
    signals: tuple[str, ...] = ()
    redirected: bool = False
    html_redirect_detected: bool = False
    final_invite_url: str | None = None
    embedded_invites: tuple[str, ...] = ()
    suspicious_redirector: bool = False
    suspicious_interstitial: bool = False
    status_code: int | None = None
    error: str | None = None


@dataclass(frozen=True)
class InviteMatch:
    url: str
    code: str
    start: int
    end: int
    embedded: bool


@dataclass(frozen=True)
class ScanVariant:
    name: str
    text: str
    signals: tuple[str, ...] = ()


@dataclass(frozen=True)
class UrlMatch:
    url: str
    start: int
    end: int
    embedded: bool


@dataclass(frozen=True)
class UrlCandidate:
    url: str
    signals: tuple[str, ...] = ()


@dataclass(frozen=True)
class ScanResult:
    raw_content: str
    urls: list[ResolvedUrl] = field(default_factory=list)
    invites: list[InviteInfo] = field(default_factory=list)
    redirect_invites: list[InviteInfo] = field(default_factory=list)
    url_detection: dict[str, Any] = field(default_factory=dict)
    invite_detection: dict[str, Any] = field(default_factory=dict)
    obfuscated_invites: bool = False

    @property
    def has_actionable_content(self) -> bool:
        return bool(self.urls or self.invites or self.redirect_invites)


def normalize_text(text: str) -> str:
    normalized = unicodedata.normalize("NFKC", text or "")
    without_invisible = _remove_invisible_characters(normalized)
    dotted = _normalize_dot_variants(without_invisible)
    return _collapse_whitespace(dotted)


def extract_invites(text: str) -> dict[str, Any]:
    variants = _build_scan_variants(text)
    invites: list[str] = []
    seen_urls: set[str] = set()
    matched_signals: set[str] = set()
    obfuscated = False

    for variant in variants:
        direct_matches = _find_embedded_invites(variant.text)
        direct_found = _merge_invite_matches(
            direct_matches,
            seen_urls,
            invites,
            matched_signals,
            variant.signals,
        )
        if direct_found and "whitespace_flattening" in variant.signals:
            obfuscated = True

        for decoded_text in _extract_decoded_substrings(variant.text):
            decoded_matches = _find_embedded_invites(decoded_text)
            decoded_found = _merge_invite_matches(
                decoded_matches,
                seen_urls,
                invites,
                matched_signals,
                variant.signals + ("percent_decoding",),
            )
            if decoded_found:
                obfuscated = True

    return {
        "invites": invites,
        "obfuscated": obfuscated,
        "variants_checked": [variant.text for variant in variants],
        "signals": sorted(matched_signals),
    }


def extract_urls_for_scanning(text: str) -> dict[str, Any]:
    variants = _build_scan_variants(text)
    candidates: list[UrlCandidate] = []
    seen_urls: set[str] = set()
    matched_signals: set[str] = set()

    for url in extract_plain_urls(text):
        _merge_url_candidate(
            UrlCandidate(url=strip_trailing_punctuation(url), signals=("url_found",)),
            candidates,
            seen_urls,
            matched_signals,
            raw_text=text,
        )

    for variant in variants:
        for match in _find_embedded_urls(variant.text):
            signals = {"url_found"}
            signals.update(variant.signals)
            if variant.signals:
                signals.add("obfuscated_url")
            if match.embedded:
                signals.add("embedded_url")
            _merge_url_candidate(
                UrlCandidate(url=strip_trailing_punctuation(match.url), signals=tuple(sorted(signals))),
                candidates,
                seen_urls,
                matched_signals,
                raw_text=text,
            )

    return {
        "urls": candidates,
        "signals": sorted(matched_signals),
    }


async def scan_message(
    content: str,
    session: aiohttp.ClientSession,
    client: discord.Client,
) -> ScanResult:
    invite_result = extract_invites(content)
    url_result = extract_urls_for_scanning(content)
    invite_candidates = [
        ParsedInvite(
            code=url.rsplit("/", 1)[-1],
            original=url,
            url=url,
        )
        for url in invite_result["invites"]
    ]

    invite_strings = {invite.url.lower() for invite in invite_candidates}
    url_candidates: list[UrlCandidate] = []
    for candidate in url_result["urls"]:
        normalized = ensure_url_scheme(candidate.url).lower()
        if normalized in invite_strings:
            continue
        url_candidates.append(candidate)

    if url_candidates:
        logger.debug("Resolved URL candidates=%s", [candidate.url for candidate in url_candidates])
    if invite_candidates:
        logger.debug(
            "Invite candidates=%s obfuscated=%s signals=%s",
            [invite.url for invite in invite_candidates],
            invite_result["obfuscated"],
            invite_result["signals"],
        )

    resolved_urls = await _resolve_urls(url_candidates, session)
    redirected_invite_candidates = _extract_redirect_invite_candidates(resolved_urls, invite_strings)
    invite_infos = await _inspect_invites(invite_candidates, client)
    redirect_invite_infos = await _inspect_invites(redirected_invite_candidates, client)

    return ScanResult(
        raw_content=content,
        urls=resolved_urls,
        invites=invite_infos,
        redirect_invites=redirect_invite_infos,
        url_detection=url_result,
        invite_detection=invite_result,
        obfuscated_invites=bool(invite_result["obfuscated"]),
    )


async def _resolve_urls(urls: list[UrlCandidate], session: aiohttp.ClientSession) -> list[ResolvedUrl]:
    results: list[ResolvedUrl] = []
    for url in urls:
        results.append(await resolve_url(url, session))
    return results


async def resolve_url(url: str | UrlCandidate, session: aiohttp.ClientSession) -> ResolvedUrl:
    if isinstance(url, UrlCandidate):
        original_url = url.url
        base_signals = set(url.signals)
    else:
        original_url = url
        base_signals = {"url_found"}

    normalized_url = ensure_url_scheme(original_url)
    original_domain = normalize_domain(normalized_url)
    suspicious_redirector = _looks_like_suspicious_redirector(original_domain)
    timeout = aiohttp.ClientTimeout(total=URL_RESOLUTION_TIMEOUT_SECONDS)

    try:
        head_result = await _inspect_url_destination(
            session,
            "HEAD",
            normalized_url,
            original_url=original_url,
            original_domain=original_domain,
            suspicious_redirector=suspicious_redirector,
            base_signals=base_signals,
            timeout=timeout,
        )
        if head_result is not None:
            if head_result.status_code in HEAD_FALLBACK_STATUSES:
                pass
            elif head_result.final_invite_url:
                return head_result
    except aiohttp.ClientError:
        head_result = None

    try:
        get_result = await _inspect_url_destination(
            session,
            "GET",
            normalized_url,
            original_url=original_url,
            original_domain=original_domain,
            suspicious_redirector=suspicious_redirector,
            base_signals=base_signals,
            timeout=timeout,
        )
        if get_result is not None:
            return get_result
    except aiohttp.ClientError as exc:
        return ResolvedUrl(
            original_url=original_url,
            normalized_url=normalized_url,
            final_url=None,
            original_domain=original_domain,
            final_domain=None,
            resolved=False,
            signals=tuple(sorted(base_signals)),
            redirected=False,
            html_redirect_detected=False,
            final_invite_url=None,
            embedded_invites=(),
            suspicious_redirector=suspicious_redirector,
            suspicious_interstitial=False,
            error=str(exc),
        )

    return ResolvedUrl(
        original_url=original_url,
        normalized_url=normalized_url,
        final_url=None,
        original_domain=original_domain,
        final_domain=None,
        resolved=False,
        signals=tuple(sorted(base_signals)),
        redirected=False,
        html_redirect_detected=False,
        final_invite_url=None,
        embedded_invites=(),
        suspicious_redirector=suspicious_redirector,
        suspicious_interstitial=False,
        error="could not resolve URL safely",
    )


async def _inspect_invites(invites: list[ParsedInvite], client: discord.Client) -> list[InviteInfo]:
    results: list[InviteInfo] = []
    for invite in invites:
        results.append(await inspect_invite(invite, client))
    return results


def summarize_scan(scan_result: ScanResult) -> dict[str, Any]:
    return {
        "url_count": len(scan_result.urls),
        "invite_count": len(scan_result.invites),
        "redirect_invite_count": len(scan_result.redirect_invites),
        "domains": [url.final_domain or url.original_domain for url in scan_result.urls],
        "url_detection": scan_result.url_detection,
        "urls": [
            {
                "original_url": url.original_url,
                "normalized_url": url.normalized_url,
                "signals": list(url.signals),
                "final_url": url.final_url,
                "final_domain": url.final_domain,
                "redirected": url.redirected,
                "html_redirect_detected": url.html_redirect_detected,
                "final_invite_url": url.final_invite_url,
                "embedded_invites": list(url.embedded_invites),
                "suspicious_redirector": url.suspicious_redirector,
                "suspicious_interstitial": url.suspicious_interstitial,
                "resolved": url.resolved,
            }
            for url in scan_result.urls
        ],
        "invite_guild_ids": [invite.guild_id for invite in scan_result.invites],
        "redirect_invite_guild_ids": [invite.guild_id for invite in scan_result.redirect_invites],
        "obfuscated_invites": scan_result.obfuscated_invites,
        "invite_detection": scan_result.invite_detection,
    }


def _build_scan_variants(text: str) -> list[ScanVariant]:
    raw_text = text or ""
    normalized = unicodedata.normalize("NFKC", raw_text)
    stripped = _remove_invisible_characters(normalized)
    dot_normalized = _normalize_dot_variants(stripped)
    unquoted = _strip_line_quote_prefixes(dot_normalized)
    decoration_stripped = _strip_decoration_noise(unquoted)
    collapsed = _collapse_whitespace(dot_normalized)
    flattened = _remove_whitespace(dot_normalized)
    normalized_collapsed = _collapse_whitespace(decoration_stripped)
    normalized_flattened = _remove_whitespace(decoration_stripped)

    seen: set[str] = set()
    ordered: list[ScanVariant] = []
    for variant in (
        ScanVariant(name="raw", text=raw_text, signals=()),
        ScanVariant(name="nfkc_normalized", text=normalized, signals=("unicode_normalization",)),
        ScanVariant(
            name="invisible_stripped",
            text=stripped,
            signals=("unicode_normalization", "invisible_characters"),
        ),
        ScanVariant(
            name="dot_normalized",
            text=dot_normalized,
            signals=(
                "unicode_normalization",
                "invisible_characters",
                "unicode_dot_normalization",
            ),
        ),
        ScanVariant(
            name="whitespace_collapsed",
            text=collapsed,
            signals=(
                "unicode_normalization",
                "invisible_characters",
                "unicode_dot_normalization",
                "whitespace_collapsed",
            ),
        ),
        ScanVariant(
            name="whitespace_removed",
            text=flattened,
            signals=(
                "unicode_normalization",
                "invisible_characters",
                "unicode_dot_normalization",
                "whitespace_flattening",
            ),
        ),
        ScanVariant(
            name="formatting_noise_stripped",
            text=normalized_collapsed,
            signals=(
                "unicode_normalization",
                "invisible_characters",
                "unicode_dot_normalization",
                "markdown_quote_stripping",
                "decoration_stripping",
            ),
        ),
        ScanVariant(
            name="formatting_noise_flattened",
            text=normalized_flattened,
            signals=(
                "unicode_normalization",
                "invisible_characters",
                "unicode_dot_normalization",
                "markdown_quote_stripping",
                "decoration_stripping",
                "whitespace_flattening",
            ),
        ),
    ):
        if not variant.text or variant.text in seen:
            continue
        seen.add(variant.text)
        ordered.append(variant)
    return ordered


def _remove_invisible_characters(text: str) -> str:
    cleaned: list[str] = []
    for char in text:
        category = unicodedata.category(char)
        if char in INVISIBLE_CODEPOINTS:
            continue
        if category == "Cf":
            continue
        cleaned.append(char)
    return "".join(cleaned)


def _collapse_whitespace(text: str) -> str:
    return WHITESPACE_RE.sub(" ", text).strip()


def _remove_whitespace(text: str) -> str:
    flattened: list[str] = []
    for char in text:
        if char.isspace():
            continue
        flattened.append(char)
    return "".join(flattened)


def _normalize_dot_variants(text: str) -> str:
    return text.translate(DOT_VARIANT_TRANSLATION)


def _strip_line_quote_prefixes(text: str) -> str:
    return LINE_QUOTE_PREFIX_RE.sub("", text)


def _strip_decoration_noise(text: str) -> str:
    return text.translate(DECORATION_TRANSLATION)


def _extract_decoded_substrings(text: str) -> list[str]:
    decoded_values: list[str] = []
    seen: set[str] = set()

    for match in PERCENT_SUBSTRING_RE.finditer(text):
        candidate = match.group("blob")
        sanitized = _sanitize_percent_blob(candidate)
        if not sanitized:
            continue
        try:
            decoded = unquote(sanitized)
        except Exception:
            continue
        if not decoded or decoded == sanitized or decoded in seen:
            continue
        seen.add(decoded)
        decoded_values.append(decoded)

    return decoded_values


def _sanitize_percent_blob(candidate: str) -> str | None:
    parts: list[str] = []
    valid_bytes = 0
    index = 0

    while index < len(candidate):
        char = candidate[index]
        if char == "%" and index + 2 < len(candidate):
            byte = candidate[index + 1 : index + 3]
            if all(_is_hex_character(value) for value in byte):
                parts.append(f"%{byte}")
                valid_bytes += 1
                index += 3
                continue

        if char == "%":
            index += 1
            continue

        if valid_bytes == 0:
            break

        if char in PERCENT_SUFFIX_CHARS:
            parts.append(char)
            index += 1
            continue

        break

    if valid_bytes < 4:
        return None
    return "".join(parts)


def _is_hex_character(value: str) -> bool:
    return value in "0123456789abcdefABCDEF"


def _merge_invite_matches(
    matches: list[InviteMatch],
    seen_urls: set[str],
    invites: list[str],
    matched_signals: set[str],
    signals: tuple[str, ...],
) -> bool:
    found_new = False
    for match in matches:
        if match.embedded:
            matched_signals.add("embedded_invite")
        matched_signals.update(signals)

        dedupe_key = match.url.lower()
        if dedupe_key in seen_urls:
            continue
        seen_urls.add(dedupe_key)
        invites.append(match.url)
        found_new = True
    return found_new


def _merge_url_candidate(
    candidate: UrlCandidate,
    candidates: list[UrlCandidate],
    seen_urls: set[str],
    matched_signals: set[str],
    *,
    raw_text: str,
) -> None:
    normalized_candidate_url = _normalize_candidate_url(candidate.url)
    if not normalized_candidate_url:
        return

    normalized_candidate = UrlCandidate(
        url=normalized_candidate_url,
        signals=candidate.signals,
    )
    dedupe_key = ensure_url_scheme(normalized_candidate.url).lower()
    if dedupe_key in seen_urls:
        if normalized_candidate.url.lower() not in raw_text.lower():
            matched_signals.update(normalized_candidate.signals)
        return

    seen_urls.add(dedupe_key)
    candidates.append(normalized_candidate)
    matched_signals.update(normalized_candidate.signals)


def _find_embedded_invites(text: str) -> list[InviteMatch]:
    matches: list[InviteMatch] = []
    seen_urls: set[str] = set()

    for match in INVITE_MATCH_RE.finditer(text):
        code = match.group("code")
        url = f"https://discord.gg/{code}"
        dedupe_key = url.lower()
        if dedupe_key in seen_urls:
            continue
        seen_urls.add(dedupe_key)

        start, end = match.span()
        matches.append(
            InviteMatch(
                url=url,
                code=code,
                start=start,
                end=end,
                embedded=_is_embedded_match(text, start, end),
            )
        )

    return matches


def _find_embedded_urls(text: str) -> list[UrlMatch]:
    matches: list[UrlMatch] = []
    seen_urls: set[str] = set()

    for match in URL_MATCH_RE.finditer(text):
        url = strip_trailing_punctuation(match.group("url"))
        dedupe_key = ensure_url_scheme(url).lower()
        if dedupe_key in seen_urls:
            continue
        seen_urls.add(dedupe_key)

        start, end = match.span()
        matches.append(
            UrlMatch(
                url=url,
                start=start,
                end=end,
                embedded=_is_embedded_match(text, start, end),
            )
        )

    return matches


def _extract_redirect_invite_candidates(
    urls: list[ResolvedUrl],
    direct_invite_urls: set[str],
) -> list[ParsedInvite]:
    invite_candidates: list[ParsedInvite] = []
    seen_urls: set[str] = set(direct_invite_urls)

    for url in urls:
        if not url.final_invite_url:
            continue

        parsed = parse_invite_url(url.final_invite_url)
        if parsed is None:
            continue

        dedupe_key = parsed.url.lower()
        if dedupe_key in seen_urls:
            continue

        seen_urls.add(dedupe_key)
        invite_candidates.append(parsed)

    return invite_candidates


async def _inspect_url_destination(
    session: aiohttp.ClientSession,
    method: str,
    url: str,
    *,
    original_url: str,
    original_domain: str | None,
    suspicious_redirector: bool,
    base_signals: set[str],
    timeout: aiohttp.ClientTimeout,
) -> ResolvedUrl | None:
    request = _open_url(
        session,
        method,
        url,
        timeout=timeout,
        max_redirects=URL_RESOLUTION_MAX_REDIRECTS,
    )
    async with request as response:
        final_url = strip_trailing_punctuation(str(response.url))
        redirected = _was_redirected(url, final_url, response)
        final_domain = normalize_domain(final_url)
        signals = set(base_signals)
        if redirected:
            signals.add("redirect_followed")

        if method == "HEAD" and response.status in HEAD_FALLBACK_STATUSES:
            return ResolvedUrl(
                original_url=original_url,
                normalized_url=url,
                final_url=final_url,
                original_domain=original_domain,
                final_domain=final_domain,
                resolved=True,
                signals=tuple(sorted(signals)),
                redirected=redirected,
                html_redirect_detected=False,
                final_invite_url=None,
                embedded_invites=(),
                suspicious_redirector=suspicious_redirector,
                suspicious_interstitial=False,
                status_code=response.status,
                error=None,
            )

        parsed_final_invite = parse_invite_url(final_url) if final_url else None
        embedded_invites: list[str] = []
        html_redirect_detected = False
        suspicious_interstitial_detected = False
        html_final_url = final_url

        if method == "GET" and _is_html_like_response(response):
            html = await _read_capped_response_text(response, HTML_INSPECTION_MAX_BYTES)
            inspection = inspect_html_redirects(html, final_url)
            embedded_invites = inspection["embedded_invites"]
            if inspection["html_redirect_detected"]:
                signals.add("html_redirect_detected")
            if inspection["suspicious_interstitial"]:
                signals.add("suspicious_interstitial")
            html_redirect_detected = inspection["html_redirect_detected"]
            suspicious_interstitial_detected = inspection["suspicious_interstitial"]
            if inspection["signals"]:
                signals.update(inspection["signals"])
            if parsed_final_invite is None and inspection["final_url"]:
                html_final_url = inspection["final_url"]
                final_domain = normalize_domain(html_final_url)
                parsed_final_invite = parse_invite_url(html_final_url)
            elif parsed_final_invite is None and embedded_invites:
                parsed_final_invite = parse_invite_url(embedded_invites[0])

        return ResolvedUrl(
            original_url=original_url,
            normalized_url=url,
            final_url=html_final_url,
            original_domain=original_domain,
            final_domain=final_domain,
            resolved=True,
            signals=tuple(sorted(signals)),
            redirected=redirected,
            html_redirect_detected=html_redirect_detected,
            final_invite_url=parsed_final_invite.url if parsed_final_invite else None,
            embedded_invites=tuple(embedded_invites),
            suspicious_redirector=suspicious_redirector,
            suspicious_interstitial=suspicious_interstitial_detected,
            status_code=response.status,
            error=None,
        )


def inspect_html_redirects(html: str, base_url: str) -> dict[str, Any]:
    embedded_invites = _normalize_invite_urls(
        [
            *extract_invites(html)["invites"],
            *extract_invites(unquote(html))["invites"],
        ]
    )
    targets: list[str] = []

    meta_target = extract_meta_refresh_target(html)
    if meta_target:
        targets.append(meta_target)
    js_redirects = extract_js_redirect_targets(html)
    targets.extend(js_redirects["targets"])
    embedded_invites = _normalize_invite_urls([*embedded_invites, *js_redirects["embedded_invites"]])

    normalized_targets: list[str] = []
    for target in targets:
        normalized = _normalize_redirect_target(target, base_url)
        if normalized:
            normalized_targets.append(normalized)

    invite_targets = _normalize_invite_urls(
        [
            candidate.url
            for target in normalized_targets
            if (candidate := parse_invite_url(target)) is not None
        ]
    )
    all_invites = _normalize_invite_urls([*invite_targets, *embedded_invites])
    html_redirect_detected = bool(normalized_targets)
    suspicious_interstitial = bool(
        INTERSTITIAL_HINT_RE.search(html) and (html_redirect_detected or all_invites)
    )

    final_url = normalized_targets[0] if normalized_targets else None
    signals: list[str] = []
    if meta_target:
        signals.append("meta_refresh_redirect")
    if js_redirects["targets"]:
        signals.append("javascript_redirect")
        signals.append("javascript_redirect_detected")
    if js_redirects["base64_payload_detected"]:
        signals.append("base64_payload_detected")
    if js_redirects["decoded_destination_detected"]:
        signals.append("decoded_destination")
    if _contains_delayed_redirect_script(html):
        signals.append("delayed_javascript_redirect")
    if embedded_invites:
        signals.append("embedded_invite")
    if suspicious_interstitial:
        signals.append("interstitial_html")

    if suspicious_interstitial and final_url is None and not all_invites:
        signals.append("review_interstitial")

    return {
        "url_found": bool(all_invites or final_url),
        "redirect_followed": False,
        "html_redirect_detected": html_redirect_detected,
        "final_url": final_url,
        "embedded_invites": all_invites,
        "suspicious_interstitial": suspicious_interstitial,
        "signals": signals,
    }


def extract_meta_refresh_target(html: str) -> str | None:
    for match in META_REFRESH_RE.finditer(html):
        content = match.group("content")
        target_match = META_REFRESH_URL_RE.search(content)
        if not target_match:
            continue
        target = target_match.group("target").strip().strip("\"'")
        if target:
            return target
    return None


def extract_js_redirect_targets(html: str) -> dict[str, Any]:
    targets: list[str] = []
    embedded_invites: list[str] = []
    seen_targets: set[str] = set()
    seen_embedded_invites: set[str] = set()
    base64_payload_detected = False
    decoded_destination_detected = False

    for script in _extract_script_blocks(html):
        variables: dict[str, str] = {}
        decoded_variable_names: set[str] = set()
        decoded_strings: list[str] = []

        for match in JS_VARIABLE_ASSIGNMENT_RE.finditer(script):
            expression = match.group("expr")
            resolved = _resolve_javascript_expression(expression, variables)
            if resolved:
                variables[match.group("name")] = resolved
                if ATOB_CALL_RE.search(expression):
                    base64_payload_detected = True
                    decoded_variable_names.add(match.group("name"))
                    decoded_strings.append(resolved)

        for match in ATOB_CALL_RE.finditer(script):
            decoded = _decode_atob_payload(match.group("payload"))
            if decoded is None:
                continue
            base64_payload_detected = True
            decoded_strings.append(decoded)

        for decoded in decoded_strings:
            for invite in extract_invites(decoded)["invites"]:
                normalized_invite = parse_invite_url(invite)
                if normalized_invite is None:
                    continue
                key = normalized_invite.url.lower()
                if key in seen_embedded_invites:
                    continue
                seen_embedded_invites.add(key)
                embedded_invites.append(normalized_invite.url)

        for redirect_match in JS_LOCATION_ASSIGNMENT_RE.finditer(script):
            target = _resolve_javascript_expression(redirect_match.group("expr"), variables)
            if _add_redirect_target(target, targets, seen_targets):
                decoded_destination_detected = decoded_destination_detected or _expression_contains_decoded_payload(
                    redirect_match.group("expr"),
                    decoded_variable_names,
                )

        for redirect_match in JS_LOCATION_CALL_RE.finditer(script):
            target = _resolve_javascript_expression(redirect_match.group("expr"), variables)
            if _add_redirect_target(target, targets, seen_targets):
                decoded_destination_detected = decoded_destination_detected or _expression_contains_decoded_payload(
                    redirect_match.group("expr"),
                    decoded_variable_names,
                )

    return {
        "targets": targets,
        "embedded_invites": embedded_invites,
        "base64_payload_detected": base64_payload_detected,
        "decoded_destination_detected": decoded_destination_detected,
    }


def _contains_delayed_redirect_script(html: str) -> bool:
    for script in _extract_script_blocks(html):
        if "setTimeout" not in script and "setInterval" not in script:
            continue
        if JS_REDIRECT_RE.search(script) or JS_LOCATION_ASSIGNMENT_RE.search(script) or JS_LOCATION_CALL_RE.search(script):
            return True
    return False


def _extract_script_blocks(html: str) -> list[str]:
    scripts = [match.group("content") for match in SCRIPT_TAG_RE.finditer(html)]
    return scripts or [html]


def _add_redirect_target(target: str | None, targets: list[str], seen: set[str]) -> bool:
    if not target:
        return False
    cleaned = target.strip()
    if not cleaned or cleaned in seen:
        return False
    seen.add(cleaned)
    targets.append(cleaned)
    return True


def _resolve_javascript_expression(expression: str | None, variables: dict[str, str] | None = None) -> str | None:
    cleaned = (expression or "").strip().strip(",")
    if not cleaned:
        return None

    if len(cleaned) >= 2 and cleaned[0] == cleaned[-1] and cleaned[0] in {"'", '"'}:
        return cleaned[1:-1]

    atob_match = ATOB_CALL_RE.fullmatch(cleaned)
    if atob_match:
        return _decode_atob_payload(atob_match.group("payload"))

    if variables and JS_IDENTIFIER_RE.fullmatch(cleaned):
        return variables.get(cleaned)

    return None


def _expression_contains_decoded_payload(expression: str | None, decoded_variable_names: set[str]) -> bool:
    cleaned = (expression or "").strip().strip(",")
    if not cleaned:
        return False
    if ATOB_CALL_RE.search(cleaned):
        return True
    if JS_IDENTIFIER_RE.fullmatch(cleaned):
        return cleaned in decoded_variable_names
    return False


def _decode_atob_payload(payload: str) -> str | None:
    if not payload or len(payload) > 2048:
        return None
    normalized = payload.strip()
    padding = (-len(normalized)) % 4
    if padding:
        normalized += "=" * padding
    try:
        decoded = base64.b64decode(normalized, validate=True)
    except (binascii.Error, ValueError):
        return None
    if not decoded or len(decoded) > BASE64_DECODE_MAX_BYTES:
        return None
    try:
        return decoded.decode("utf-8")
    except UnicodeDecodeError:
        return decoded.decode("utf-8", errors="ignore") or None


async def _read_capped_response_text(response: Any, max_bytes: int) -> str:
    body = await response.read()
    if not body:
        return ""
    return body[:max_bytes].decode("utf-8", errors="ignore")


def _is_html_like_response(response: Any) -> bool:
    content_type = getattr(response, "content_type", None)
    if content_type:
        normalized = str(content_type).split(";", 1)[0].strip().lower()
        return normalized in HTML_LIKE_CONTENT_TYPES

    headers = getattr(response, "headers", {}) or {}
    header_value = headers.get("Content-Type", "")
    normalized_header = header_value.split(";", 1)[0].strip().lower()
    return normalized_header in HTML_LIKE_CONTENT_TYPES


def _normalize_redirect_target(target: str, base_url: str) -> str | None:
    cleaned = strip_trailing_punctuation(target.strip().strip("\"'"))
    if not cleaned:
        return None
    if cleaned.lower().startswith(("javascript:", "data:", "mailto:")):
        return None
    parsed = urlparse(cleaned)
    if parsed.scheme in {"http", "https"}:
        return cleaned
    return urljoin(base_url, cleaned)


def _normalize_invite_urls(urls: list[str]) -> list[str]:
    normalized: list[str] = []
    seen: set[str] = set()
    for url in urls:
        parsed = parse_invite_url(url)
        if parsed is None:
            continue
        key = parsed.url.lower()
        if key in seen:
            continue
        seen.add(key)
        normalized.append(parsed.url)
    return normalized


def _normalize_candidate_url(url: str) -> str:
    cleaned = strip_trailing_punctuation(_normalize_dot_variants(url or ""))
    return cleaned.rstrip("\\")


def _open_url(
    session: aiohttp.ClientSession,
    method: str,
    url: str,
    *,
    timeout: aiohttp.ClientTimeout,
    max_redirects: int,
):
    request_args = {
        "allow_redirects": True,
        "timeout": timeout,
        "max_redirects": max_redirects,
    }
    if method == "HEAD":
        return session.head(url, **request_args)
    return session.get(url, **request_args)


def _was_redirected(normalized_url: str, final_url: str, response: Any) -> bool:
    if normalized_url.rstrip("/") != final_url.rstrip("/"):
        return True
    return bool(getattr(response, "history", ()))


def _looks_like_suspicious_redirector(domain: str | None) -> bool:
    if not domain:
        return False
    return any(domain == candidate or domain.endswith(f".{candidate}") for candidate in SUSPICIOUS_REDIRECTOR_DOMAINS)


def _is_embedded_match(text: str, start: int, end: int) -> bool:
    prefix = text[max(0, start - 8) : start]
    left_char = text[start - 1] if start > 0 else ""
    right_char = text[end] if end < len(text) else ""
    if prefix.endswith("://"):
        return False
    return bool(
        (left_char and not left_char.isspace() and left_char not in "<([{'\"")
        or (right_char and not right_char.isspace() and right_char not in ">)]}'\"")
    )
