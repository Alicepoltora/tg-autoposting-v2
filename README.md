# Telegram Monitoring & Translation Bot

Production-ready Telegram bot that monitors multiple source channels, cleans content from links/hashtags, translates non-Russian content to Russian, and forwards everything to a target channel.

## Features
- **Real-time Monitoring**: Follows multiple Telegram channels using a User account session for full access.
- **Auto-Translation**: Automatically detects non-Russian languages and translates them via Google Translate API.
- **Content Cleaning**: Strip links, mentions, and hashtags using customizable regex rules.
- **Media Preservation**: Full support for photos, videos, and captions.
- **Management Mini App**: Built-in React-based Telegram Mini App to manage source channels and cleaning rules.
- **Persistent Storage**: Prevent duplicates using SQLite.

## Deployment Structure
- `bot.py`: Main bot logic for monitoring and forwarding.
- `api.py`: FastAPI backend to manage configuration and service status.
- `index.html`: The Mini App frontend (Single HTML/React/Tailwind setup).
- `config_manager.py`: Handles `config.json` operations.
- `database.py`: SQLite persistence layer.
- `cleaner.py`: Modular regex-based text cleaning.
- `*.service`: Systemd units for managing the bot and API on Linux/VPS.

## How to Deploy to a New Server
1. Clone this repository.
2. Create and activate a Virtual Environment: `python -m venv venv` and `source venv/bin/activate`.
3. Install dependencies: `pip install -r requirements.txt`.
4. Create a `.env` file with your credentials:
   ```env
   TG_API_ID=your_id
   TG_API_HASH=your_hash
   TG_SESSION_NAME=bot_session
   ```
5. Run `python bot.py` once to authorize via phone/code.
6. Install systemd services:
   ```bash
   cp *.service /etc/systemd/system/
   systemctl daemon-reload
   systemctl enable --now telegram-bot bot-api
   ```
7. Set up the Mini App via @BotFather to point to your server IP on port 80.
