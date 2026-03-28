# Project Aegis

Project Aegis is a Discord moderation bot focused on suspicious invite and link detection. It scans message content for direct invites, hidden invites, redirect chains, HTML interstitials, and obfuscated URLs, then decides whether to ignore, allow, review, or block the message.

The project is designed for communities that want stronger protection against phishing-style lure messages, fake support links, disguised Discord invites, and suspicious redirector pages.

Created by VersionBear at [versionbear.com](https://versionbear.com).

## What It Does

- Scans every non-bot message sent in a guild
- Extracts and normalizes Discord invite links, even when they are obfuscated
- Resolves normal URLs and follows redirects to identify final destinations
- Detects HTML and JavaScript redirect behavior
- Flags suspicious redirector hosts such as static hosting or short-lived landing pages
- Scores uncertain cases for moderator review instead of hard-blocking everything
- Supports allowlists and blocklists for domains and Discord server IDs
- Sends moderator alerts to a configured channel
- Can run in `monitor` mode for safe testing before enforcement
- Supports optional follow-up action after a blocked message: `none`, `timeout`, `kick`, or `ban`

## Detection Model

Project Aegis combines deterministic rules with a simple risk scoring system.

Hard block cases include:

- URLs that redirect to a Discord invite
- Messages matching a blocked domain
- Messages matching a blocked Discord server ID
- Suspicious redirector pages with interstitial or redirect behavior

Review cases are scored based on signals such as:

- Obfuscated or hidden URLs
- Hidden or decoded invite payloads
- Unresolved invites or URLs
- JavaScript or meta refresh redirects
- Suspicious wording like fake support-style prompts
- Repeated suspicious activity from the same user
- New accounts associated with suspicious content

Outcomes:

- `ignore`: nothing actionable found
- `allow`: content matched allowed destinations or did not score high enough
- `review_low`: logged quietly
- `review_high`: sent to the moderator alert channel
- `block`: message is deleted and optional punishment is applied

## Slash Commands

All slash commands are under `/aegis` and require moderator-level permissions.

- `/aegis scan`
  Analyze sample text manually and return a detailed scan embed.
- `/aegis status`
  Show current runtime status, configured lists, thresholds, mode, and punishment settings.
- `/aegis recent`
  Show recent high-confidence events tracked in memory.
- `/aegis mode`
  Switch between `monitor` and `active`.
- `/aegis setup`
  Configure the mod-log channel, punishment type, timeout length, and optional appeal URL.
- `/aegis domain`
  Add or remove domains from the allowlist or blocklist.
- `/aegis server`
  Add or remove Discord server IDs from the allowlist or blocklist.
- `/aegis lists`
  View the current allowlist and blocklist data.

## How Data Is Stored

Project Aegis uses MongoDB for persistent configuration and list storage.

The bot stores:

- Runtime config such as mod-log channel, punishment mode, timeout minutes, and appeal URL
- Allowed server IDs
- Blocked server IDs
- Allowed domains
- Blocked domains

This means list and setup changes made through slash commands persist across restarts.

## Requirements

- Python 3
- A Discord bot token
- A MongoDB database

Python dependencies are listed in [requirements.txt](requirements.txt):

- `discord.py`
- `aiohttp`
- `python-dotenv`
- `pymongo[srv]`

## Setup

### 1. Clone the repository

```powershell
git clone https://github.com/VersionBear/project-aegis.git
cd project-aegis
```

### 2. Create and activate a virtual environment

```powershell
python -m venv .venv
.venv\Scripts\Activate.ps1
```

### 3. Install dependencies

```powershell
pip install -r requirements.txt
```

### 4. Create your local environment file

Copy [.env.example](.env.example) to `.env` and fill in your real values.

Example:

```env
DISCORD_BOT_TOKEN=your-discord-bot-token
HTTP_TIMEOUT_SECONDS=10
LOG_LEVEL=INFO
MONGODB_URI=mongodb+srv://username:password@cluster.mongodb.net/?retryWrites=true&w=majority
MONGODB_DB_NAME=project_aegis
MONGODB_COLLECTION_NAME=settings
```

### 5. Start the bot

```powershell
python bot.py
```

## Discord Bot Configuration

Your Discord application should have these bot intents enabled:

- `Guilds`
- `Guild Messages`
- `Message Content`
- `Server Members`

The bot also needs enough guild permissions to do its job. The exact set depends on how you configure punishments, but in practice you should expect to need:

- Read messages / view channels
- Send messages
- Embed links
- Manage messages
- Moderate members if using timeouts
- Kick members if using kicks
- Ban members if using bans

The slash command group itself is created with moderator-oriented permissions, and command access is restricted in code to users with moderation-related guild permissions.

## Recommended First-Time Setup

Start conservatively:

1. Launch the bot.
2. Run `/aegis setup` to set a mod-log channel.
3. Set `/aegis mode` to `monitor`.
4. Use `/aegis scan` with known-safe and known-bad examples.
5. Add trusted domains and servers to the allowlists.
6. Add known-bad domains or server IDs to the blocklists.
7. Review alerts in your mod-log channel.
8. Switch to `active` once you are comfortable with the behavior.

## Project Structure

- [bot.py](bot.py)
  Entry point and Discord client lifecycle.
- [link_scanner.py](link_scanner.py)
  URL and invite extraction, normalization, resolution, and redirect inspection.
- [risk_engine.py](risk_engine.py)
  Scoring and final verdict logic.
- [actions.py](actions.py)
  Message deletion, punishment actions, and moderator alert delivery.
- [aegis_commands.py](aegis_commands.py)
  Slash commands and moderation control surface.
- [config.py](config.py)
  Environment loading and settings assembly.
- [mongo_store.py](mongo_store.py)
  Mongo-backed persistence layer.

## Testing

The repository includes unit tests:

- [test_aegis_commands.py](test_aegis_commands.py)
- [test_link_scanner.py](test_link_scanner.py)

Run them with:

```powershell
python -m unittest
```

## Security Notes

- Never commit a real `.env` file.
- Rotate tokens or database credentials immediately if they were ever exposed.
- Start in `monitor` mode before enabling enforcement in a production server.
- Review list changes carefully since allowlists can bypass review/block outcomes.
- The bot performs network resolution of URLs, so set reasonable outbound restrictions if you operate in a tightly controlled environment.

## Limitations

- Like any moderation bot, it can still produce false positives and false negatives.
- Invite resolution depends on Discord API availability and bot permissions.
- URL inspection is intentionally bounded by timeouts, redirect limits, and response size caps.
- Recent event history and alert suppression state are kept in memory, so they reset when the process restarts.

## License

This project is licensed under the MIT License. See [LICENSE](LICENSE).
