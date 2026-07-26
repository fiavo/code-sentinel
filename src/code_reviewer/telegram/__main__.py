#!/usr/bin/env python3
"""
Bot runner script.

Usage:
    # Set token via environment variable
    export TELEGRAM_BOT_TOKEN="your-bot-token"
    python -m code_reviewer.telegram.bot

    # Or pass token as argument
    python -m code_reviewer.telegram.bot --token "your-bot-token"
"""

import sys
import os
import argparse


def main():
    parser = argparse.ArgumentParser(description="Run CodeSentinel Telegram Bot")
    parser.add_argument(
        "--token",
        type=str,
        help="Telegram bot token (or set TELEGRAM_BOT_TOKEN env var)",
    )
    args = parser.parse_args()
    
    token = args.token or os.getenv("TELEGRAM_BOT_TOKEN")
    
    if not token:
        print("❌ Error: Telegram bot token not provided!")
        print("\nUsage:")
        print("  export TELEGRAM_BOT_TOKEN='your-token'")
        print("  python -m code_reviewer.telegram.bot")
        print("\nOr:")
        print("  python -m code_reviewer.telegram.bot --token 'your-token'")
        print("\nGet a token from @BotFather on Telegram")
        sys.exit(1)
    
    from .bot import TelegramBot
    
    bot = TelegramBot(token=token)
    bot.run()


if __name__ == "__main__":
    main()
