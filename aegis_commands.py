from __future__ import annotations

from collections import deque
from dataclasses import dataclass
from datetime import datetime
from typing import Literal

import discord
from discord import app_commands

from actions import get_alert_cache_stats
from config import Settings, save_domain_set, save_id_set, save_mod_log_channel_id, save_punishment_settings
from link_scanner import ScanResult, scan_message
from risk_engine import REVIEW_HIGH_SCORE, REVIEW_LOW_SCORE, Verdict, evaluate_message_scan
from utils import normalize_domain


EnforcementMode = Literal["active", "monitor"]
BlockPunishment = Literal["none", "timeout", "kick", "ban"]
_enforcement_mode: EnforcementMode = "active"
_recent_events: deque["RecentEvent"] = deque(maxlen=25)
_recent_event_counter = 0


@dataclass(frozen=True)
class AnalysisReport:
    scan_result: ScanResult
    verdict: Verdict


@dataclass(frozen=True)
class RecentEvent:
    event_id: str
    timestamp: datetime
    user_id: int
    user_name: str
    action: str
    verdict: str
    reasons: tuple[str, ...]
    score: int


DOMAIN_FILES = {
    "allowlist": "allowed_domains",
    "blocklist": "blocked_domains",
}
SERVER_FILES = {
    "allowlist": "allowed_servers",
    "blocklist": "blocked_servers",
}


async def analyze_text(
    text: str,
    session,
    client: discord.Client,
    settings: Settings,
    *,
    user_id: int | None = None,
    account_age_seconds: float | None = None,
) -> AnalysisReport:
    scan_result = await scan_message(text, session, client)
    verdict = evaluate_message_scan(
        scan_result,
        settings,
        user_id=user_id,
        account_age_seconds=account_age_seconds,
    )
    return AnalysisReport(scan_result=scan_result, verdict=verdict)


def build_scan_embed(report: AnalysisReport, text: str) -> discord.Embed:
    scan_result = report.scan_result
    verdict = report.verdict
    invite_urls = [invite.url for invite in [*scan_result.invites, *scan_result.redirect_invites]]
    url_lines = []
    for url in scan_result.urls[:5]:
        details = [url.original_url]
        if url.final_url and url.final_url != url.original_url:
            details.append(f"-> {url.final_url}")
        flags = []
        if url.redirected:
            flags.append("redirected")
        if url.html_redirect_detected:
            flags.append("html-redirect")
        if url.suspicious_interstitial:
            flags.append("interstitial")
        if url.final_invite_url:
            flags.append(f"invite {url.final_invite_url}")
        if flags:
            details.append(f"({'/'.join(flags)})")
        url_lines.append(" ".join(details))

    signals = sorted(
        {
            *scan_result.url_detection.get("signals", []),
            *scan_result.invite_detection.get("signals", []),
            *(signal for url in scan_result.urls for signal in url.signals),
        }
    )

    embed = discord.Embed(
        title="Aegis Scan",
        color=_verdict_color(verdict.verdict),
        description=_truncate(text, 400) or "(empty)",
    )
    embed.add_field(name="Verdict", value=f"{verdict.verdict} (score {verdict.score})", inline=False)
    embed.add_field(name="Reasons", value=_field_text(verdict.reasons), inline=False)
    embed.add_field(name="Invites", value=_field_text(invite_urls), inline=False)
    embed.add_field(name="URLs", value=_field_text(url_lines), inline=False)
    embed.add_field(name="Signals", value=_field_text(signals), inline=False)
    embed.add_field(
        name="Notes",
        value=(
            "Invite or URL only surfaced after normalization."
            if {"percent_decoding", "whitespace_flattening", "embedded_invite", "obfuscated_url"} & set(signals)
            else "No extra normalization tricks were needed."
        ),
        inline=False,
    )
    return embed


def build_status_embed(settings: Settings) -> discord.Embed:
    alert_stats = get_alert_cache_stats()
    embed = discord.Embed(
        title="Aegis Status",
        color=discord.Color.blurple(),
    )
    embed.add_field(name="Scanning", value="enabled", inline=True)
    embed.add_field(name="Mode", value=get_enforcement_mode(), inline=True)
    embed.add_field(
        name="Mod Log Channel",
        value=f"<#{settings.mod_log_channel_id}>" if settings.mod_log_channel_id else "not configured",
        inline=True,
    )
    embed.add_field(
        name="Domains",
        value=(
            f"allow {len(settings.allowed_domains)}\n"
            f"block {len(settings.blocked_domains)}"
        ),
        inline=True,
    )
    embed.add_field(
        name="Servers",
        value=(
            f"allow {len(settings.allowed_server_ids)}\n"
            f"block {len(settings.blocked_server_ids)}"
        ),
        inline=True,
    )
    embed.add_field(
        name="Runtime",
        value=(
            f"recent {len(_recent_events)}\n"
            f"alert-cache {alert_stats['cache_entries']}\n"
            f"thresholds {REVIEW_LOW_SCORE}/{REVIEW_HIGH_SCORE}"
        ),
        inline=True,
    )
    embed.add_field(
        name="Block Punishment",
        value=(
            f"delete message\n"
            f"punishment {settings.block_punishment}\n"
            f"timeout minutes {settings.action_timeout_minutes}\n"
            f"appeal {'set' if settings.appeal_form_url else 'not set'}"
        ),
        inline=True,
    )
    return embed


def build_recent_embed(limit: int = 5) -> discord.Embed:
    visible_events = [event for event in reversed(_recent_events) if event.verdict in {"block", "review_high"}][:limit]
    embed = discord.Embed(
        title="Aegis Recent",
        color=discord.Color.orange(),
    )
    if not visible_events:
        embed.description = "No recent high-confidence events recorded."
        return embed

    for event in visible_events:
        embed.add_field(
            name=f"{event.timestamp.strftime('%H:%M:%S')} {event.action}",
            value=(
                f"user `{event.user_name}` (`{event.user_id}`)\n"
                f"score `{event.score}`\n"
                f"reason `{event.reasons[0] if event.reasons else 'n/a'}`\n"
                f"id `{event.event_id}`"
            ),
            inline=False,
        )
    return embed


def record_recent_event(
    *,
    user_id: int,
    user_name: str,
    action: str,
    verdict: Verdict,
) -> str:
    global _recent_event_counter

    _recent_event_counter += 1
    event_id = f"evt-{_recent_event_counter:04d}"
    _recent_events.append(
        RecentEvent(
            event_id=event_id,
            timestamp=datetime.utcnow(),
            user_id=user_id,
            user_name=user_name,
            action=action,
            verdict=verdict.verdict,
            reasons=tuple(verdict.reasons),
            score=verdict.score,
        )
    )
    return event_id


def set_enforcement_mode(mode: EnforcementMode) -> EnforcementMode:
    global _enforcement_mode
    _enforcement_mode = mode
    return _enforcement_mode


def get_enforcement_mode() -> EnforcementMode:
    return _enforcement_mode


def _is_moderator(user) -> bool:
    permissions = getattr(user, "guild_permissions", None)
    if permissions is None:
        return False
    return bool(
        permissions.administrator
        or permissions.manage_guild
        or permissions.manage_messages
        or permissions.moderate_members
    )


def update_domain_entry(settings: Settings, list_name: str, action: str, domain: str) -> str:
    normalized = normalize_domain(domain)
    if not normalized:
        raise ValueError("Enter a valid domain.")

    target_set = settings.allowed_domains if list_name == "allowlist" else settings.blocked_domains
    other_set = settings.blocked_domains if list_name == "allowlist" else settings.allowed_domains

    if action == "add":
        target_set.add(normalized)
        other_set.discard(normalized)
    else:
        target_set.discard(normalized)

    save_domain_set(DOMAIN_FILES[list_name], target_set)
    save_domain_set(DOMAIN_FILES["blocklist" if list_name == "allowlist" else "allowlist"], other_set)
    return normalized


def update_server_entry(settings: Settings, list_name: str, action: str, server_id: int) -> int:
    target_set = settings.allowed_server_ids if list_name == "allowlist" else settings.blocked_server_ids
    other_set = settings.blocked_server_ids if list_name == "allowlist" else settings.allowed_server_ids

    if action == "add":
        target_set.add(server_id)
        other_set.discard(server_id)
    else:
        target_set.discard(server_id)

    save_id_set(SERVER_FILES[list_name], target_set)
    save_id_set(SERVER_FILES["blocklist" if list_name == "allowlist" else "allowlist"], other_set)
    return server_id


def set_mod_log_channel(settings: Settings, channel_id: int) -> int:
    save_mod_log_channel_id(channel_id)
    object.__setattr__(settings, "mod_log_channel_id", channel_id)
    return channel_id


def set_block_punishment(
    settings: Settings,
    *,
    punishment: BlockPunishment,
    timeout_minutes: int,
    appeal_form_url: str | None,
) -> tuple[str, int, str | None]:
    minutes = max(1, timeout_minutes)
    appeal_url = appeal_form_url.strip() if appeal_form_url else None
    save_punishment_settings(
        block_punishment=punishment,
        timeout_minutes=minutes,
        appeal_form_url=appeal_url,
    )
    object.__setattr__(settings, "block_punishment", punishment)
    object.__setattr__(settings, "appeal_form_url", appeal_url)
    object.__setattr__(settings, "action_timeout_minutes", minutes)
    return punishment, minutes, appeal_url


def build_mode_embed(mode: EnforcementMode) -> discord.Embed:
    embed = discord.Embed(
        title="Aegis Mode Updated",
        color=discord.Color.gold() if mode == "monitor" else discord.Color.green(),
        description=f"Aegis mode set to `{mode}`.",
    )
    embed.add_field(
        name="Behavior",
        value="Monitor logs detections without destructive actions." if mode == "monitor" else "Active mode enforces block actions normally.",
        inline=False,
    )
    return embed


def build_setup_embed(settings: Settings, channel_id: int) -> discord.Embed:
    embed = discord.Embed(
        title="Aegis Setup Complete",
        color=discord.Color.green(),
        description=f"Mod alerts will be sent to <#{channel_id}>.",
    )
    embed.add_field(name="Mode", value=get_enforcement_mode(), inline=True)
    embed.add_field(name="Allowlists", value=f"domains {len(settings.allowed_domains)} / servers {len(settings.allowed_server_ids)}", inline=True)
    embed.add_field(name="Blocklists", value=f"domains {len(settings.blocked_domains)} / servers {len(settings.blocked_server_ids)}", inline=True)
    embed.add_field(
        name="Punishments",
        value=(
            "delete message\n"
            f"punishment {settings.block_punishment}\n"
            f"timeout minutes {settings.action_timeout_minutes}\n"
            f"appeal {settings.appeal_form_url or 'not set'}"
        ),
        inline=True,
    )
    embed.add_field(
        name="Next Steps",
        value="Use `/aegis scan` to debug samples, `/aegis domain` and `/aegis server` to tune lists, `/aegis lists` to inspect data, and `/aegis mode` to switch between monitor and active.",
        inline=False,
    )
    return embed


def build_list_update_embed(entry_type: str, list_name: str, action: str, value: str) -> discord.Embed:
    verb = "added to" if action == "add" else "removed from"
    embed = discord.Embed(
        title="Aegis List Updated",
        color=discord.Color.green() if action == "add" else discord.Color.orange(),
        description=f"`{value}` {verb} the {list_name} {entry_type} list.",
    )
    return embed


def build_lists_embed(settings: Settings, scope: str) -> discord.Embed:
    embed = discord.Embed(
        title="Aegis Lists",
        color=discord.Color.blurple(),
        description=f"Showing `{scope}` list data.",
    )

    if scope in {"all", "domains"}:
        embed.add_field(name="Allowed Domains", value=_field_text(sorted(settings.allowed_domains)[:20]), inline=False)
        embed.add_field(name="Blocked Domains", value=_field_text(sorted(settings.blocked_domains)[:20]), inline=False)
    if scope in {"all", "servers"}:
        embed.add_field(
            name="Allowed Servers",
            value=_field_text([str(server_id) for server_id in sorted(settings.allowed_server_ids)[:20]]),
            inline=False,
        )
        embed.add_field(
            name="Blocked Servers",
            value=_field_text([str(server_id) for server_id in sorted(settings.blocked_server_ids)[:20]]),
            inline=False,
        )
    return embed


def build_aegis_group(bot: discord.Client, settings: Settings) -> app_commands.Group:
    class AegisGroup(app_commands.Group):
        def __init__(self) -> None:
            super().__init__(
                name="aegis",
                description="Project Aegis moderation tools",
                default_permissions=discord.Permissions(manage_messages=True),
                guild_only=True,
            )

        async def interaction_check(self, interaction: discord.Interaction) -> bool:
            if interaction.guild is None or not _is_moderator(interaction.user):
                if interaction.response.is_done():
                    await interaction.followup.send("Moderator permissions are required.", ephemeral=True)
                else:
                    await interaction.response.send_message("Moderator permissions are required.", ephemeral=True)
                return False
            return True

        @app_commands.command(name="scan", description="Analyze suspicious text with the Aegis scanner")
        @app_commands.describe(text="Text to analyze")
        async def scan(self, interaction: discord.Interaction, text: str) -> None:
            await interaction.response.defer(ephemeral=True, thinking=True)
            created_at = getattr(interaction.user, "created_at", None)
            account_age_seconds = None
            if created_at is not None:
                account_age_seconds = (discord.utils.utcnow() - created_at).total_seconds()
            report = await analyze_text(
                text,
                bot.http_session,
                bot,
                settings,
                user_id=interaction.user.id,
                account_age_seconds=account_age_seconds,
            )
            await interaction.followup.send(embed=build_scan_embed(report, text), ephemeral=True)

        @app_commands.command(name="status", description="Show Aegis operational status")
        async def status(self, interaction: discord.Interaction) -> None:
            await interaction.response.send_message(embed=build_status_embed(settings), ephemeral=True)

        @app_commands.command(name="recent", description="Show recent high-confidence Aegis events")
        async def recent(self, interaction: discord.Interaction) -> None:
            await interaction.response.send_message(embed=build_recent_embed(), ephemeral=True)

        @app_commands.command(name="mode", description="Set Aegis enforcement mode")
        @app_commands.describe(mode="monitor logs detections without destructive actions; active enforces blocks")
        @app_commands.choices(
            mode=[
                app_commands.Choice(name="monitor", value="monitor"),
                app_commands.Choice(name="active", value="active"),
            ]
        )
        async def mode(self, interaction: discord.Interaction, mode: app_commands.Choice[str]) -> None:
            active_mode = set_enforcement_mode(mode.value)  # type: ignore[arg-type]
            await interaction.response.send_message(embed=build_mode_embed(active_mode), ephemeral=True)

        @app_commands.command(name="setup", description="Configure the Aegis mod-log channel and block punishments")
        @app_commands.describe(
            channel="Channel for mod alerts. Defaults to the current channel.",
            punishment="What Aegis should do after deleting a blocked message",
            timeout_minutes="Timeout length in minutes when timeout punishment is selected",
            appeal_form_url="Optional appeal form for kick or ban notices",
        )
        @app_commands.choices(
            punishment=[
                app_commands.Choice(name="none", value="none"),
                app_commands.Choice(name="timeout", value="timeout"),
                app_commands.Choice(name="kick", value="kick"),
                app_commands.Choice(name="ban", value="ban"),
            ]
        )
        async def setup(
            self,
            interaction: discord.Interaction,
            channel: discord.TextChannel | None = None,
            punishment: app_commands.Choice[str] | None = None,
            timeout_minutes: app_commands.Range[int, 1, 10080] | None = None,
            appeal_form_url: str | None = None,
        ) -> None:
            target_channel = channel or interaction.channel
            if not isinstance(target_channel, discord.TextChannel):
                await interaction.response.send_message("Pick a text channel for mod alerts.", ephemeral=True)
                return
            channel_id = set_mod_log_channel(settings, target_channel.id)
            selected_punishment, minutes, appeal_url = set_block_punishment(
                settings,
                punishment=settings.block_punishment if punishment is None else punishment.value,  # type: ignore[arg-type]
                timeout_minutes=settings.action_timeout_minutes if timeout_minutes is None else timeout_minutes,
                appeal_form_url=settings.appeal_form_url if appeal_form_url is None else appeal_form_url,
            )
            object.__setattr__(settings, "block_punishment", selected_punishment)
            object.__setattr__(settings, "appeal_form_url", appeal_url)
            object.__setattr__(settings, "action_timeout_minutes", minutes)
            await interaction.response.send_message(embed=build_setup_embed(settings, channel_id), ephemeral=True)

        @app_commands.command(name="domain", description="Manage domain allowlist and blocklist entries")
        @app_commands.describe(list_name="Which list to manage", action="Add or remove the domain", domain="Domain to update")
        @app_commands.choices(
            list_name=[
                app_commands.Choice(name="allowlist", value="allowlist"),
                app_commands.Choice(name="blocklist", value="blocklist"),
            ],
            action=[
                app_commands.Choice(name="add", value="add"),
                app_commands.Choice(name="remove", value="remove"),
            ],
        )
        async def domain(
            self,
            interaction: discord.Interaction,
            list_name: app_commands.Choice[str],
            action: app_commands.Choice[str],
            domain: str,
        ) -> None:
            try:
                normalized = update_domain_entry(settings, list_name.value, action.value, domain)
            except ValueError as exc:
                await interaction.response.send_message(str(exc), ephemeral=True)
                return
            await interaction.response.send_message(
                embed=build_list_update_embed("domain", list_name.value, action.value, normalized),
                ephemeral=True,
            )

        @app_commands.command(name="server", description="Manage server allowlist and blocklist entries")
        @app_commands.describe(list_name="Which list to manage", action="Add or remove the server", server_id="Server ID to update")
        @app_commands.choices(
            list_name=[
                app_commands.Choice(name="allowlist", value="allowlist"),
                app_commands.Choice(name="blocklist", value="blocklist"),
            ],
            action=[
                app_commands.Choice(name="add", value="add"),
                app_commands.Choice(name="remove", value="remove"),
            ],
        )
        async def server(
            self,
            interaction: discord.Interaction,
            list_name: app_commands.Choice[str],
            action: app_commands.Choice[str],
            server_id: str,
        ) -> None:
            try:
                normalized_server_id = update_server_entry(settings, list_name.value, action.value, int(server_id))
            except ValueError:
                await interaction.response.send_message("Enter a numeric Discord server ID.", ephemeral=True)
                return
            await interaction.response.send_message(
                embed=build_list_update_embed("server", list_name.value, action.value, str(normalized_server_id)),
                ephemeral=True,
            )

        @app_commands.command(name="lists", description="Show the current allow/block list data")
        @app_commands.describe(scope="Which list data to show")
        @app_commands.choices(
            scope=[
                app_commands.Choice(name="all", value="all"),
                app_commands.Choice(name="domains", value="domains"),
                app_commands.Choice(name="servers", value="servers"),
            ]
        )
        async def lists(self, interaction: discord.Interaction, scope: app_commands.Choice[str]) -> None:
            await interaction.response.send_message(
                embed=build_lists_embed(settings, scope.value),
                ephemeral=True,
            )

    return AegisGroup()


def _reset_runtime_state() -> None:
    global _recent_event_counter, _enforcement_mode
    _recent_events.clear()
    _recent_event_counter = 0
    _enforcement_mode = "active"


def _field_text(values: list[str] | tuple[str, ...]) -> str:
    return _truncate("\n".join(values) if values else "none", 1024)


def _truncate(value: str, limit: int) -> str:
    if len(value) <= limit:
        return value
    return f"{value[: limit - 3]}..."


def _verdict_color(verdict: str) -> discord.Color:
    if verdict == "block":
        return discord.Color.red()
    if verdict == "review_high":
        return discord.Color.orange()
    if verdict == "review_low":
        return discord.Color.gold()
    return discord.Color.green()
