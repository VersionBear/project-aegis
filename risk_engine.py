from __future__ import annotations

import re
import time
from dataclasses import dataclass, field

from config import Settings
from link_scanner import ResolvedUrl, ScanResult
from utils import domain_matches


VerdictType = str
REVIEW_HIGH_SCORE = 50
REVIEW_LOW_SCORE = 10
SUSPICIOUS_EVENT_WINDOW_SECONDS = 600
NEW_ACCOUNT_THRESHOLD_SECONDS = 7 * 24 * 60 * 60
SUSPICIOUS_WORDING_RE = re.compile(r"\b(?:ticket|support|help|assist|verify)\b", re.IGNORECASE)
_recent_suspicious_events: dict[int, list[float]] = {}


@dataclass(frozen=True)
class Verdict:
    verdict: VerdictType
    reasons: list[str] = field(default_factory=list)
    matched_domains: list[str] = field(default_factory=list)
    matched_server_ids: list[int] = field(default_factory=list)
    score: int = 0
    alert_level: str = "none"


def evaluate_message_scan(
    scan_result: ScanResult,
    settings: Settings,
    *,
    user_id: int | None = None,
    account_age_seconds: float | None = None,
) -> Verdict:
    if not scan_result.has_actionable_content:
        return Verdict(verdict="ignore", reasons=["no actionable links found"])

    blocked_servers = _collect_blocked_servers(scan_result, settings)
    redirected_invites = [
        url.final_invite_url
        for url in scan_result.urls
        if url.final_invite_url
    ]
    if redirected_invites:
        return Verdict(
            verdict="block",
            reasons=["URL redirected to a Discord invite"],
            matched_server_ids=sorted(blocked_servers),
            score=100,
            alert_level="main",
        )

    blocked_domains = _collect_blocked_domains(scan_result.urls, settings)
    if blocked_domains:
        return Verdict(
            verdict="block",
            reasons=["matched blocked domain"],
            matched_domains=sorted(blocked_domains),
            score=100,
            alert_level="main",
        )

    if blocked_servers:
        return Verdict(
            verdict="block",
            reasons=["matched blocked Discord server"],
            matched_server_ids=sorted(blocked_servers),
            score=100,
            alert_level="main",
        )

    suspicious_redirector_interstitials = [
        url.original_url
        for url in scan_result.urls
        if url.suspicious_redirector and (url.suspicious_interstitial or url.html_redirect_detected)
    ]
    if suspicious_redirector_interstitials:
        return Verdict(
            verdict="block",
            reasons=["suspicious redirector HTML interstitial detected"],
            matched_domains=sorted(_collect_review_domains(scan_result.urls)),
            score=100,
            alert_level="main",
        )

    allowed_domains = _collect_allowed_domains(scan_result.urls, settings)
    allowed_servers = _collect_allowed_servers(scan_result, settings)
    all_urls_allowed = all(_is_allowed_url(url, settings) for url in scan_result.urls)
    all_invites_allowed = all(
        invite.guild_id is not None and invite.guild_id in settings.allowed_server_ids
        for invite in _all_invites(scan_result)
    )

    if scan_result.urls and all_urls_allowed and _all_invites(scan_result) and not all_invites_allowed:
        all_urls_allowed = True

    if scan_result.urls and all_urls_allowed and (_all_invites(scan_result) and all_invites_allowed):
        return Verdict(
            verdict="allow",
            reasons=["all resolved destinations matched allow lists"],
            matched_domains=sorted(allowed_domains),
            matched_server_ids=sorted(allowed_servers),
        )

    if not scan_result.urls and _all_invites(scan_result) and all_invites_allowed:
        return Verdict(
            verdict="allow",
            reasons=["all resolved destinations matched allow lists"],
            matched_domains=sorted(allowed_domains),
            matched_server_ids=sorted(allowed_servers),
        )

    score, reasons = _score_review_risk(
        scan_result,
        settings,
        all_urls_allowed=all_urls_allowed,
        all_invites_allowed=all_invites_allowed,
        user_id=user_id,
        account_age_seconds=account_age_seconds,
    )
    review_domains = sorted(_collect_review_domains(scan_result.urls))
    review_server_ids = sorted(_collect_review_server_ids(scan_result))

    if score >= REVIEW_HIGH_SCORE:
        return Verdict(
            verdict="review_high",
            reasons=reasons,
            matched_domains=review_domains,
            matched_server_ids=review_server_ids,
            score=score,
            alert_level="main",
        )

    if score >= REVIEW_LOW_SCORE:
        return Verdict(
            verdict="review_low",
            reasons=reasons,
            matched_domains=review_domains,
            matched_server_ids=review_server_ids,
            score=score,
            alert_level="quiet",
        )

    return Verdict(
        verdict="allow",
        reasons=["all resolved destinations matched allow lists"],
        matched_domains=sorted(allowed_domains),
        matched_server_ids=sorted(allowed_servers),
    )


def _collect_blocked_domains(urls: list[ResolvedUrl], settings: Settings) -> set[str]:
    matches: set[str] = set()
    for url in urls:
        for domain in (url.final_domain, url.original_domain):
            if domain and domain_matches(domain, settings.blocked_domains):
                matches.add(domain)
    return matches


def _collect_allowed_domains(urls: list[ResolvedUrl], settings: Settings) -> set[str]:
    matches: set[str] = set()
    for url in urls:
        if url.final_invite_url:
            continue
        domain = url.final_domain or url.original_domain
        if domain and domain_matches(domain, settings.allowed_domains):
            matches.add(domain)
    return matches


def _is_allowed_url(url: ResolvedUrl, settings: Settings) -> bool:
    if url.final_invite_url:
        return True
    domain = url.final_domain or url.original_domain
    return bool(domain and domain_matches(domain, settings.allowed_domains))


def _collect_blocked_servers(scan_result: ScanResult, settings: Settings) -> set[int]:
    return {
        invite.guild_id
        for invite in _all_invites(scan_result)
        if invite.guild_id is not None and invite.guild_id in settings.blocked_server_ids
    }


def _collect_allowed_servers(scan_result: ScanResult, settings: Settings) -> set[int]:
    return {
        invite.guild_id
        for invite in _all_invites(scan_result)
        if invite.guild_id is not None and invite.guild_id in settings.allowed_server_ids
    }


def _collect_review_domains(urls: list[ResolvedUrl]) -> set[str]:
    matches: set[str] = set()
    for url in urls:
        for domain in (url.final_domain, url.original_domain):
            if domain:
                matches.add(domain)
    return matches


def _collect_review_server_ids(scan_result: ScanResult) -> set[int]:
    return {
        invite.guild_id
        for invite in _all_invites(scan_result)
        if invite.guild_id is not None
    }


def _score_review_risk(
    scan_result: ScanResult,
    settings: Settings,
    *,
    all_urls_allowed: bool,
    all_invites_allowed: bool,
    user_id: int | None,
    account_age_seconds: float | None,
) -> tuple[int, list[str]]:
    score = 0
    reasons: list[str] = []
    signals = _collect_scan_signals(scan_result)

    unresolved_suspicious_redirectors = any(
        url.suspicious_redirector and not url.resolved for url in scan_result.urls
    )
    if unresolved_suspicious_redirectors:
        score += 45
        reasons.append("suspicious redirector URL could not be resolved safely")

    suspicious_interstitials = any(
        url.suspicious_interstitial and not url.final_invite_url for url in scan_result.urls
    )
    if suspicious_interstitials:
        score += 40
        reasons.append("suspicious HTML interstitial could not be resolved confidently")

    unresolved_invites = any(not invite.resolved for invite in _all_invites(scan_result))
    if unresolved_invites:
        score += 35
        reasons.append("could not resolve one or more Discord invites safely")

    if _all_invites(scan_result) and not all_invites_allowed:
        score += 25
        reasons.append("one or more Discord invites were not present in allow/block lists")

    if scan_result.urls and not all_urls_allowed:
        score += 10
        reasons.append("one or more URLs were not present in allow/block lists")

    if scan_result.obfuscated_invites or "obfuscated_url" in signals:
        score += 25
        reasons.append("obfuscation detected in invite or URL")

    if {"embedded_invite", "percent_decoding", "base64_payload_detected", "decoded_destination"} & signals:
        score += 25
        reasons.append("decoded or hidden destination payload detected")

    if "html_redirect_detected" in signals or "javascript_redirect_detected" in signals:
        score += 30
        reasons.append("client-side redirect behavior detected")

    if any(url.suspicious_redirector for url in scan_result.urls):
        score += 15
        reasons.append("suspicious hosting domain detected")

    if SUSPICIOUS_WORDING_RE.search(scan_result.raw_content):
        score += 15
        reasons.append("suspicious support-style wording detected")

    previous_events = _count_recent_suspicious_events(user_id)
    if previous_events >= 2 and score > 0:
        score += 20
        reasons.append("repeated suspicious activity from the same user")

    if account_age_seconds is not None and account_age_seconds <= NEW_ACCOUNT_THRESHOLD_SECONDS and score > 0:
        score += 10
        reasons.append("new account associated with suspicious event")

    if score > 0:
        _record_suspicious_event(user_id)

    return score, _dedupe_reasons(reasons)


def _collect_scan_signals(scan_result: ScanResult) -> set[str]:
    signals = set(scan_result.url_detection.get("signals", []))
    signals.update(scan_result.invite_detection.get("signals", []))
    for url in scan_result.urls:
        signals.update(url.signals)
    return signals


def _count_recent_suspicious_events(user_id: int | None) -> int:
    if user_id is None:
        return 0
    now = time.monotonic()
    timestamps = [
        timestamp
        for timestamp in _recent_suspicious_events.get(user_id, [])
        if now - timestamp <= SUSPICIOUS_EVENT_WINDOW_SECONDS
    ]
    _recent_suspicious_events[user_id] = timestamps
    return len(timestamps)


def _record_suspicious_event(user_id: int | None) -> None:
    if user_id is None:
        return
    now = time.monotonic()
    timestamps = _recent_suspicious_events.setdefault(user_id, [])
    timestamps.append(now)
    _recent_suspicious_events[user_id] = [
        timestamp for timestamp in timestamps if now - timestamp <= SUSPICIOUS_EVENT_WINDOW_SECONDS
    ]


def _dedupe_reasons(reasons: list[str]) -> list[str]:
    deduped: list[str] = []
    seen: set[str] = set()
    for reason in reasons:
        if reason in seen:
            continue
        seen.add(reason)
        deduped.append(reason)
    return deduped


def _reset_recent_suspicious_events() -> None:
    _recent_suspicious_events.clear()


def _all_invites(scan_result: ScanResult):
    return [*scan_result.invites, *scan_result.redirect_invites]
