from __future__ import annotations

import logging
import time
from dataclasses import dataclass, field
from datetime import timedelta

import discord

from config import Settings
from risk_engine import Verdict


logger = logging.getLogger("aegis.actions")
quiet_review_logger = logging.getLogger("aegis.review_low")
ALERT_COOLDOWN_SECONDS = 300
_alert_cache: dict[tuple[str, str, tuple[str, ...], tuple[int, ...]], "_AlertState"] = {}


@dataclass
class _AlertState:
    last_sent_at: float = 0.0
    suppressed_count: int = 0
    recent_user_ids: set[int] = field(default_factory=set)


async def take_block_action(
    message: discord.Message,
    verdict: Verdict,
    settings: Settings,
) -> None:
    await _delete_message(message)
    await _apply_block_punishment(message, settings)
    await _send_mod_alert(message, verdict, settings, action_taken="block")


async def notify_block_detected(
    message: discord.Message,
    verdict: Verdict,
    settings: Settings,
) -> None:
    await _send_mod_alert(message, verdict, settings, action_taken="block_detected")


async def handle_review(
    message: discord.Message,
    verdict: Verdict,
    settings: Settings,
) -> None:
    if verdict.alert_level == "main":
        await _send_mod_alert(message, verdict, settings, action_taken=verdict.verdict)
        return

    _log_quiet_review(message, verdict)


async def _delete_message(message: discord.Message) -> None:
    try:
        await message.delete()
    except discord.NotFound:
        logger.info("Message %s was already deleted", message.id)
    except discord.Forbidden:
        logger.warning("Missing permission to delete message %s", message.id)
    except discord.HTTPException as exc:
        logger.warning("Failed to delete message %s: %s", message.id, exc)


async def _apply_block_punishment(message: discord.Message, settings: Settings) -> None:
    member = message.author if isinstance(message.author, discord.Member) else None
    if member is None:
        return

    if member.guild_permissions.administrator or member.guild_permissions.manage_messages:
        logger.info("Skipping block punishment for staff member %s", member.id)
        return

    me = message.guild.me if message.guild else None
    if me is None:
        return

    punishment = settings.block_punishment
    if punishment == "none":
        return

    if member.top_role >= me.top_role:
        logger.info("Skipping %s for member %s because role hierarchy prevents it", punishment, member.id)
        return

    await _send_user_punishment_notice(member, punishment, settings)

    if punishment == "timeout":
        if not me.guild_permissions.moderate_members:
            logger.warning("Bot cannot timeout member %s due to missing moderate_members permission", member.id)
            return
        try:
            await member.timeout(
                timedelta(minutes=settings.action_timeout_minutes),
                reason="Project Aegis blocked suspicious link/invite",
            )
        except discord.Forbidden:
            logger.warning("Missing permission to timeout member %s", message.author.id)
        except discord.HTTPException as exc:
            logger.warning("Failed to timeout member %s: %s", message.author.id, exc)
        return

    if punishment == "kick":
        if not me.guild_permissions.kick_members:
            logger.warning("Bot cannot kick member %s due to missing kick_members permission", member.id)
            return
        try:
            await member.kick(reason="Project Aegis blocked suspicious link/invite")
        except discord.Forbidden:
            logger.warning("Missing permission to kick member %s", message.author.id)
        except discord.HTTPException as exc:
            logger.warning("Failed to kick member %s: %s", message.author.id, exc)
        return

    if punishment == "ban":
        if not me.guild_permissions.ban_members:
            logger.warning("Bot cannot ban member %s due to missing ban_members permission", member.id)
            return
        try:
            await member.ban(reason="Project Aegis blocked suspicious link/invite", delete_message_days=1)
        except TypeError:
            await member.ban(reason="Project Aegis blocked suspicious link/invite")
        except discord.Forbidden:
            logger.warning("Missing permission to ban member %s", message.author.id)
        except discord.HTTPException as exc:
            logger.warning("Failed to ban member %s: %s", message.author.id, exc)


async def _send_user_punishment_notice(member: discord.Member, punishment: str, settings: Settings) -> None:
    if punishment not in {"kick", "ban"}:
        return

    notice = f"You were removed by Project Aegis after posting a blocked suspicious link. Action: {punishment}."
    if settings.appeal_form_url:
        notice = f"{notice}\nAppeal form: {settings.appeal_form_url}"
    try:
        await member.send(notice)
    except (discord.Forbidden, discord.HTTPException):
        logger.info("Could not DM member %s before %s", member.id, punishment)


async def _send_mod_alert(
    message: discord.Message,
    verdict: Verdict,
    settings: Settings,
    action_taken: str,
) -> None:
    aggregate_note = _register_alert(message, verdict, action_taken)
    if aggregate_note is None:
        logger.info(
            "Suppressed duplicate %s alert for user=%s reasons=%s",
            action_taken,
            message.author.id,
            verdict.reasons,
        )
        return

    if settings.mod_log_channel_id is None:
        return

    channel = message.guild.get_channel(settings.mod_log_channel_id) if message.guild else None
    if channel is None:
        return

    embed = discord.Embed(
        title=f"Aegis {action_taken.replace('_', ' ').title()} Alert",
        color=discord.Color.red() if action_taken.startswith("block") else discord.Color.orange(),
    )
    embed.add_field(name="User", value=f"{message.author} (`{message.author.id}`)", inline=False)
    embed.add_field(name="Channel", value=message.channel.mention, inline=False)
    embed.add_field(name="Verdict", value=verdict.verdict, inline=True)
    embed.add_field(name="Score", value=str(verdict.score), inline=True)
    embed.add_field(name="Reasons", value="\n".join(verdict.reasons) or "n/a", inline=False)
    embed.add_field(
        name="Matched Domains",
        value=", ".join(verdict.matched_domains) if verdict.matched_domains else "none",
        inline=False,
    )
    embed.add_field(
        name="Matched Server IDs",
        value=", ".join(str(server_id) for server_id in verdict.matched_server_ids)
        if verdict.matched_server_ids
        else "none",
        inline=False,
    )

    content_preview = message.content
    if len(content_preview) > 1024:
        content_preview = f"{content_preview[:1021]}..."
    embed.add_field(name="Message Content", value=content_preview or "(empty)", inline=False)
    if aggregate_note:
        embed.add_field(name="Recent Activity", value=aggregate_note, inline=False)

    try:
        await channel.send(embed=embed)
    except discord.Forbidden:
        logger.warning("Missing permission to send mod-log alert in channel %s", channel.id)
    except discord.HTTPException as exc:
        logger.warning("Failed to send mod-log alert: %s", exc)


def _log_quiet_review(message: discord.Message, verdict: Verdict) -> None:
    aggregate_note = _register_alert(message, verdict, verdict.verdict)
    if aggregate_note is None:
        return

    quiet_review_logger.info(
        "Low-priority review user=%s channel=%s verdict=%s score=%s domains=%s servers=%s reasons=%s summary=%s content=%r",
        message.author.id,
        getattr(message.channel, "id", "unknown"),
        verdict.verdict,
        verdict.score,
        verdict.matched_domains,
        verdict.matched_server_ids,
        verdict.reasons,
        aggregate_note,
        message.content,
    )


def _register_alert(message: discord.Message, verdict: Verdict, action_taken: str) -> str | None:
    key = _build_alert_key(verdict, action_taken)
    state = _alert_cache.setdefault(key, _AlertState())
    now = time.monotonic()
    state.recent_user_ids.add(message.author.id)

    if state.last_sent_at and now - state.last_sent_at < ALERT_COOLDOWN_SECONDS:
        state.suppressed_count += 1
        return None

    note = ""
    if state.suppressed_count:
        note = (
            f"Suppressed {state.suppressed_count} similar events in the last "
            f"{ALERT_COOLDOWN_SECONDS // 60} minutes across {len(state.recent_user_ids)} user(s)."
        )
    state.last_sent_at = now
    state.suppressed_count = 0
    state.recent_user_ids = {message.author.id}
    return note


def _build_alert_key(
    verdict: Verdict,
    action_taken: str,
) -> tuple[str, str, tuple[str, ...], tuple[int, ...]]:
    scope = ",".join(verdict.matched_domains) or ",".join(str(server_id) for server_id in verdict.matched_server_ids) or "global"
    return (
        action_taken,
        scope,
        tuple(verdict.reasons),
        tuple(verdict.matched_server_ids),
    )


def _reset_alert_cache() -> None:
    _alert_cache.clear()


def get_alert_cache_stats() -> dict[str, int]:
    return {
        "cache_entries": len(_alert_cache),
        "cooldown_seconds": ALERT_COOLDOWN_SECONDS,
    }
