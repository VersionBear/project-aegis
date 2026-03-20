import logging

import discord

from actions import handle_review, notify_block_detected, take_block_action
from aegis_commands import build_aegis_group, get_enforcement_mode, record_recent_event
from config import get_settings
from link_scanner import scan_message
from risk_engine import evaluate_message_scan

settings = get_settings()

logging.basicConfig(
    level=getattr(logging, settings.log_level, logging.INFO),
    format="%(asctime)s %(levelname)s [%(name)s] %(message)s",
)

logger = logging.getLogger("aegis.bot")


class AegisBot(discord.Client):
    def __init__(self) -> None:
        intents = discord.Intents.default()
        intents.guilds = True
        intents.messages = True
        intents.message_content = True
        intents.members = True
        super().__init__(intents=intents)
        self.tree = discord.app_commands.CommandTree(self)

    async def on_ready(self) -> None:
        logger.info("Logged in as %s (%s)", self.user, self.user.id if self.user else "unknown")

    async def on_message(self, message: discord.Message) -> None:
        if message.author.bot or message.guild is None:
            return

        try:
            scan_result = await scan_message(message.content, self.http_session, self)
            account_age_seconds = None
            author_created_at = getattr(message.author, "created_at", None)
            if author_created_at is not None:
                account_age_seconds = (discord.utils.utcnow() - author_created_at).total_seconds()
            verdict = evaluate_message_scan(
                scan_result,
                settings,
                user_id=message.author.id,
                account_age_seconds=account_age_seconds,
            )
            logger.debug(
                "Message %s scan complete: urls=%s invites=%s verdict=%s score=%s alert=%s",
                message.id,
                len(scan_result.urls),
                len(scan_result.invites),
                verdict.verdict,
                verdict.score,
                verdict.alert_level,
            )
        except Exception:
            logger.exception("Failed to scan message %s", message.id)
            return

        if verdict.verdict == "ignore":
            return

        if verdict.verdict in {"review_high", "review_low"}:
            await handle_review(message, verdict, settings)
            record_recent_event(
                user_id=message.author.id,
                user_name=str(message.author),
                action=verdict.verdict,
                verdict=verdict,
            )
            return

        if verdict.verdict == "block":
            if get_enforcement_mode() == "monitor":
                await notify_block_detected(message, verdict, settings)
                record_recent_event(
                    user_id=message.author.id,
                    user_name=str(message.author),
                    action="block_detected",
                    verdict=verdict,
                )
                return

            await take_block_action(message, verdict, settings)
            record_recent_event(
                user_id=message.author.id,
                user_name=str(message.author),
                action="block",
                verdict=verdict,
            )

    async def setup_hook(self) -> None:
        import aiohttp

        timeout = aiohttp.ClientTimeout(total=settings.http_timeout_seconds)
        self.http_session = aiohttp.ClientSession(timeout=timeout)
        self.tree.add_command(build_aegis_group(self, settings))
        await self.tree.sync()

    async def close(self) -> None:
        session = getattr(self, "http_session", None)
        if session is not None and not session.closed:
            await session.close()
        await super().close()


def main() -> None:
    bot = AegisBot()
    bot.run(settings.discord_bot_token, log_handler=None)


if __name__ == "__main__":
    main()
