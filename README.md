# New Safety Bot

## Setup

```zsh
cd GG
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements.txt
cp .env.example .env
```

Edit `.env`:

```env
SAFETY_BOT_TOKEN=your_separate_bot_token
```

## Discord Portal

In the Discord Developer Portal, open the bot application and enable:

- Message Content Intent

Invite it with:

- View Channels
- Send Messages
- Embed Links
- Read Message History

## Run

```zsh
cd GG
source .venv/bin/activate
python bot.py
```
