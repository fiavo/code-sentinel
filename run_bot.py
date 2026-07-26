#!/usr/bin/env python3
"""Run CodeSentinel Telegram Bot"""

import os
import sys

# Add src to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "src"))

from code_reviewer.telegram.bot import TelegramBot

if __name__ == "__main__":
    # Set API key from environment variable
    if not os.getenv("OPENAI_API_KEY"):
        print("⚠️  Warning: OPENAI_API_KEY not set!")
        print("Set it with: export OPENAI_API_KEY='your-key'")
    
    bot = TelegramBot(token="8919289317:AAFsLhOrV0a_o5FSGpLVuqJHCScku_Q0tYE")
    bot.run()
