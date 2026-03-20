from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Iterable
from urllib.parse import unquote, urlparse


URL_PATTERN = re.compile(
    r"(?P<url>(?:https?://|www\.)[^\s<>()]+)",
    re.IGNORECASE,
)

DISCORD_INVITE_PATTERN = re.compile(
    r"(?P<invite>(?:https?://)?(?:www\.)?(?:discord\.gg|discord\.com/invite|discordapp\.com/invite)/(?P<code>[A-Za-z0-9-]+))",
    re.IGNORECASE,
)
DISCORD_INVITE_FRAGMENT_PATTERN = re.compile(
    r"(?P<invite>(?:discord\.gg|discord\.com/invite|discordapp\.com/invite)/(?P<code>[A-Za-z0-9-]+))",
    re.IGNORECASE,
)
DISCORD_REDIRECT_INVITE_PATTERN = re.compile(
    r"(?P<invite>discord:[^\s<>()\]]*?(?:discord\.gg|discord\.com/invite|discordapp\.com/invite)/(?P<code>[A-Za-z0-9-]+))",
    re.IGNORECASE,
)
PERCENT_ENCODED_BLOB_PATTERN = re.compile(r"(?:%[0-9A-Fa-f]{2}){4,}")
OBFUSCATION_STRIP_PATTERN = re.compile(r"[\s\u200b-\u200f\u2060\ufeff]+")
DECORATION_STRIP_PATTERN = re.compile(r"[<>\[\]\(\)\{\}\*`|]+")

TRAILING_PUNCTUATION = ".,!?;:'\")]>}"


@dataclass(frozen=True)
class ParsedInvite:
    code: str
    original: str
    url: str


@dataclass(frozen=True)
class DetectionText:
    source: str
    text: str


def strip_trailing_punctuation(value: str) -> str:
    return value.rstrip(TRAILING_PUNCTUATION)


def ensure_url_scheme(value: str) -> str:
    if value.lower().startswith(("http://", "https://")):
        return value
    return f"https://{value}"


def normalize_domain(value: str) -> str | None:
    candidate = value.strip().lower()
    if not candidate:
        return None

    if "://" not in candidate:
        candidate = f"https://{candidate}"

    parsed = urlparse(candidate)
    host = parsed.hostname
    if not host:
        return None

    host = host.rstrip(".")
    if host.startswith("www."):
        host = host[4:]
    return host or None


def domain_matches(domain: str | None, known_domains: Iterable[str]) -> bool:
    if not domain:
        return False

    lowered = domain.lower()
    for candidate in known_domains:
        if lowered == candidate or lowered.endswith(f".{candidate}"):
            return True
    return False


def extract_urls(content: str) -> list[str]:
    urls: list[str] = []
    seen_urls: set[str] = set()

    for candidate in iter_detection_texts(content):
        for match in URL_PATTERN.finditer(candidate.text):
            cleaned = strip_trailing_punctuation(match.group("url"))
            normalized = cleaned.lower()
            if not cleaned or normalized in seen_urls:
                continue
            seen_urls.add(normalized)
            urls.append(cleaned)
    return urls


def parse_invite_url(value: str) -> ParsedInvite | None:
    for candidate in iter_detection_texts(value):
        cleaned = strip_trailing_punctuation(candidate.text)
        for pattern in (
            DISCORD_INVITE_PATTERN,
            DISCORD_REDIRECT_INVITE_PATTERN,
            DISCORD_INVITE_FRAGMENT_PATTERN,
        ):
            match = pattern.search(cleaned)
            if not match:
                continue

            code = match.group("code")
            original = strip_trailing_punctuation(match.group("invite"))
            return ParsedInvite(code=code, original=original, url=f"https://discord.gg/{code}")
    return None


def collapse_obfuscation(text: str) -> str:
    collapsed = OBFUSCATION_STRIP_PATTERN.sub("", text)
    return DECORATION_STRIP_PATTERN.sub("", collapsed)


def decode_percent_encoded_blob(value: str, max_rounds: int = 3) -> str:
    decoded = value
    for _ in range(max_rounds):
        next_value = unquote(decoded)
        if next_value == decoded:
            break
        decoded = next_value
    return decoded


def iter_detection_texts(content: str) -> list[DetectionText]:
    candidates: list[DetectionText] = [DetectionText(source="raw", text=content)]
    seen_texts: set[str] = {content}

    collapsed = collapse_obfuscation(content)
    if collapsed and collapsed not in seen_texts:
        candidates.append(DetectionText(source="collapsed", text=collapsed))
        seen_texts.add(collapsed)

    for source_text in list(candidates):
        for match in PERCENT_ENCODED_BLOB_PATTERN.finditer(source_text.text):
            decoded = decode_percent_encoded_blob(match.group(0))
            if decoded and decoded not in seen_texts:
                candidates.append(
                    DetectionText(source=f"{source_text.source}:percent_decoded", text=decoded)
                )
                seen_texts.add(decoded)

            collapsed_decoded = collapse_obfuscation(decoded)
            if collapsed_decoded and collapsed_decoded not in seen_texts:
                candidates.append(
                    DetectionText(
                        source=f"{source_text.source}:percent_decoded:collapsed",
                        text=collapsed_decoded,
                    )
                )
                seen_texts.add(collapsed_decoded)

    return candidates


def extract_invites(content: str) -> list[ParsedInvite]:
    invites: list[ParsedInvite] = []
    seen_codes: set[str] = set()

    for candidate in iter_detection_texts(content):
        for pattern in (
            DISCORD_INVITE_PATTERN,
            DISCORD_REDIRECT_INVITE_PATTERN,
            DISCORD_INVITE_FRAGMENT_PATTERN,
        ):
            for match in pattern.finditer(candidate.text):
                parsed = parse_invite_url(match.group("invite"))
                if parsed is None:
                    continue
                normalized_code = parsed.code.lower()
                if normalized_code in seen_codes:
                    continue
                seen_codes.add(normalized_code)
                invites.append(parsed)
    return invites
