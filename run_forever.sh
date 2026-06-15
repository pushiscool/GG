#!/bin/bash

cd "$(dirname "$0")" || exit 1

if [ -f .venv/bin/activate ]; then
    source .venv/bin/activate
fi

while true; do
    echo "$(date '+%Y-%m-%d %H:%M:%S') [keepalive] launching bot.py"
    python bot.py
    code=$?
    if [ "$code" -eq 0 ]; then
        echo "$(date '+%Y-%m-%d %H:%M:%S') [keepalive] clean exit (code 0); stopping."
        break
    fi
    echo "$(date '+%Y-%m-%d %H:%M:%S') [keepalive] bot.py died (code=$code); restarting in 5s"
    sleep 5
done
