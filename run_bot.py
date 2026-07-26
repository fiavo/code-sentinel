#!/usr/bin/env python3
"""Run CodeSentinel Telegram Bot with AI support"""

import os
import sys

# Add src to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "src"))

# Set API key and base URL from environment variables
# For 9router: export OPENAI_API_KEY="your-key" && export OPENAI_BASE_URL="https://9router.com/api/v1"
if not os.getenv("OPENAI_API_KEY"):
    print("⚠️  Warning: OPENAI_API_KEY not set!")
    print("Set it with: export OPENAI_API_KEY='your-key'")
if not os.getenv("OPENAI_BASE_URL"):
    os.environ["OPENAI_BASE_URL"] = "https://api.openai.com/v1"

from code_reviewer.telegram.bot import TelegramBot

if __name__ == "__main__":
    bot = TelegramBot(token="8919289317:AAFsLhOrV0a_o5FSGpLVuqJHCScku_Q0tYE")
    bot.run()
