from __future__ import annotations

import logging
from dataclasses import dataclass

import discord

from utils import ParsedInvite


logger = logging.getLogger("aegis.invites")


@dataclass(frozen=True)
class InviteInfo:
    code: str
    url: str
    guild_id: int | None
    guild_name: str | None
    guild_description: str | None
    approximate_member_count: int | None
    approximate_presence_count: int | None
    channel_id: int | None
    channel_name: str | None
    inviter_id: int | None
    resolved: bool
    error: str | None = None


async def inspect_invite(invite: ParsedInvite, client: discord.Client) -> InviteInfo:
    # Prefer discord.py's authenticated invite lookup over a raw HTTP request.
    # The library handles the bot token, response parsing, and Discord API quirks
    # more reliably than a manual unauthenticated GET to the public invite endpoint.
    try:
        resolved_invite = await client.fetch_invite(
            invite.url,
            with_counts=True,
            with_expiration=True,
        )
    except discord.NotFound:
        logger.debug("Invite code=%s could not be resolved: invalid or expired", invite.code)
        return InviteInfo(
            code=invite.code,
            url=invite.url,
            guild_id=None,
            guild_name=None,
            guild_description=None,
            approximate_member_count=None,
            approximate_presence_count=None,
            channel_id=None,
            channel_name=None,
            inviter_id=None,
            resolved=False,
            error="invite is invalid or expired",
        )
    except discord.HTTPException as exc:
        logger.warning("Invite lookup failed for code %s: %s", invite.code, exc)
        return InviteInfo(
            code=invite.code,
            url=invite.url,
            guild_id=None,
            guild_name=None,
            guild_description=None,
            approximate_member_count=None,
            approximate_presence_count=None,
            channel_id=None,
            channel_name=None,
            inviter_id=None,
            resolved=False,
            error=str(exc),
        )

    guild = resolved_invite.guild
    channel = resolved_invite.channel
    inviter = resolved_invite.inviter

    logger.debug(
        "Invite resolved code=%s guild_id=%s guild_name=%r channel_id=%s channel_name=%r",
        invite.code,
        getattr(guild, "id", None),
        getattr(guild, "name", None),
        getattr(channel, "id", None),
        getattr(channel, "name", None),
    )

    return InviteInfo(
        code=invite.code,
        url=invite.url,
        guild_id=getattr(guild, "id", None),
        guild_name=getattr(guild, "name", None),
        guild_description=getattr(guild, "description", None),
        approximate_member_count=resolved_invite.approximate_member_count,
        approximate_presence_count=resolved_invite.approximate_presence_count,
        channel_id=getattr(channel, "id", None),
        channel_name=getattr(channel, "name", None),
        inviter_id=getattr(inviter, "id", None),
        resolved=True,
        error=None,
    )
