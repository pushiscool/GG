# New Safety Bot

This is a standalone Discord bot for scam and explicit-content review alerts.

When it marks something dangerous, it sends:

```text
<@920819377627099166> btw for review
```

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
REVIEW_CHANNEL_ID=the_channel_id_where_review_alerts_should_go
POST_SAFETY_MARKERS=true
```

If `REVIEW_CHANNEL_ID` is empty or invalid, review alerts go in the same channel as the message.

## Discord Portal

In the Discord Developer Portal, open the separate bot application and enable:

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

## Test

Send a normal image. It should say:

```text
(image marked safe)
```

Send scam text like:

```text
MrBeast free $500 claim now https://bit.ly/fake
```

It should say:

```text
(message marked dangerous)
```

And it should post:

```text
<@920819377627099166> btw for review
```
