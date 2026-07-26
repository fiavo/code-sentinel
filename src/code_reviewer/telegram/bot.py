"""
Telegram Bot integration for CodeSentinel.
"""

import os
import asyncio
from typing import Optional
from pathlib import Path

from ..core.analyzer import CodeAnalyzer, AnalyzerConfig
from ..core.models import Severity, ReviewResult
from ..fixers.auto_fix import AutoFixer
from .ai_features import generate_code_from_persian, translate_code, explain_code, detect_language
from .ai_provider import AIProvider


# Main keyboard buttons
MAIN_KEYBOARD = [
    ["🔍 Review", "🔧 Fix"],
    ["📊 Stats", "📈 Analyze"],
    ["💬 Chat", "🌍 Translate"],
    ["✍️ Write", "🤖 AI"],
    ["📎 Upload", "❓ Help"],
]


class TelegramBot:
    """
    Telegram bot for code review.
    
    Supports:
    - Code block analysis
    - File upload review
    - Auto-fix suggestions
    - Inline queries
    - Custom keyboards
    - AI-powered analysis
    - Group and private chats
    
    Example:
        bot = TelegramBot(token="YOUR_BOT_TOKEN")
        bot.run()
    """
    
    def __init__(self, token: Optional[str] = None):
        self.token = token or os.getenv("TELEGRAM_BOT_TOKEN", "")
        self.analyzer = CodeAnalyzer()
        self.fixer = AutoFixer()
        self.ai_provider = AIProvider()
        self._bot = None
        self._dispatcher = None
        self._user_files: dict[int, dict] = {}  # Store last file per user
    
    def _setup_handlers(self):
        """Setup bot command handlers."""
        from aiogram import Bot, Dispatcher, F
        from aiogram.client.default import DefaultBotProperties
        from aiogram.filters import Command, CommandStart
        from aiogram.types import (
            Message, 
            CallbackQuery,
            InlineQuery,
            InlineQueryResultArticle,
            InputTextMessageContent,
            KeyboardButton,
            ReplyKeyboardMarkup,
        )
        from aiogram.enums import ParseMode, InlineQueryResultType
        
        self._bot = Bot(
            token=self.token,
            default=DefaultBotProperties(parse_mode=ParseMode.HTML)
        )
        self._dispatcher = Dispatcher()
        
        dp = self._dispatcher
        
        # Create reply keyboard
        def get_main_keyboard():
            return ReplyKeyboardMarkup(
                keyboard=[
                    [KeyboardButton(text="🔍 Review"), KeyboardButton(text="🔧 Fix")],
                    [KeyboardButton(text="📊 Stats"), KeyboardButton(text="📈 Analyze")],
                    [KeyboardButton(text="💬 Chat"), KeyboardButton(text="🌍 Translate")],
                    [KeyboardButton(text="✍️ Write"), KeyboardButton(text="🤖 AI")],
                    [KeyboardButton(text="📎 Upload"), KeyboardButton(text="❓ Help")],
                ],
                resize_keyboard=True,
                one_time_keyboard=False,
            )
        
        # Start command
        @dp.message(CommandStart())
        async def cmd_start(message: Message):
            text = """
🛡️ <b>CodeSentinel Bot</b>

AI-powered code review at your fingertips!

<b>How to use:</b>
1. Send a code block with <code>/review</code>
2. Or upload a file and type <code>/review</code>
3. Or just paste code and add <code>/analyze</code>
4. Use keyboard buttons for quick access!

<b>Keyboard Buttons:</b>
🔍 Review - Review code or file
🔧 Fix - Auto-fix issues
📊 Stats - Code statistics
📈 Analyze - Quick analysis
💬 Chat - Smart code conversation
🌍 Translate - Code translation
✍️ Write - Generate code from Persian
📎 Upload - Upload a file
❓ Help - Show this help

<b>Supported languages:</b>
Python, JavaScript, TypeScript, Java, Go, Rust, C/C++, and more!
"""
            await message.reply(text, reply_markup=get_main_keyboard())
        
        # Help command
        @dp.message(Command("help"))
        async def cmd_help(message: Message):
            text = """
🛡️ <b>CodeSentinel Bot</b>

<b>Commands:</b>
/review - Review code or file
/analyze - Quick code analysis
/fix - Auto-fix issues
/stats - Code statistics
/help - Show this help

<b>Inline Mode:</b>
Type <code>@code_sentinelbot</code> in any chat followed by code

<b>Keyboard Buttons:</b>
Use the buttons below for quick access!
"""
            await message.reply(text, reply_markup=get_main_keyboard())
        
        # Handle keyboard button: Review
        @dp.message(F.text == "🔍 Review")
        async def btn_review(message: Message):
            code, language = self._extract_code(message)
            
            # Check for stored file
            if not code and message.from_user:
                user_id = message.from_user.id
                if user_id in self._user_files:
                    stored = self._user_files[user_id]
                    code = stored["content"]
                    language = stored["language"]
                    await message.reply(f"📄 Reviewing stored file: {stored['name']}")
            
            if not code:
                await message.reply(
                    "📝 Send code to review:\n\n"
                    "1. Type code directly\n"
                    "2. Upload a file\n"
                    "3. Send code block with ```"
                )
                return
            
            result = self.analyzer.analyze_code(code, language)
            response = f"""🔍 <b>Code Review</b>

{self._format_result(result)}

💡 <b>Tip:</b> Use buttons below for more actions!"""
            await message.reply(response, reply_markup=get_main_keyboard())
        
        # Handle keyboard button: Fix
        @dp.message(F.text == "🔧 Fix")
        async def btn_fix(message: Message):
            code, language = self._extract_code(message)
            
            if not code and message.from_user:
                user_id = message.from_user.id
                if user_id in self._user_files:
                    stored = self._user_files[user_id]
                    code = stored["content"]
                    language = stored["language"]
            
            if not code:
                await message.reply("📝 Send code to fix.")
                return
            
            result = self.analyzer.analyze_code(code, language)
            
            if not result.issues:
                await message.reply("✅ No issues found! Code looks good.")
                return
            
            fixed_code, changes = self.fixer.fix(code, result.issues)
            
            if changes:
                response = f"""🔧 <b>Fixed Code:</b>

<code>{self._escape_html(fixed_code)}</code>

📝 <b>Changes made:</b>
{chr(10).join(f"• {c}" for c in changes[:5])}

💡 <b>Tip:</b> Review the changes before using!"""
                await message.reply(response, reply_markup=get_main_keyboard())
            else:
                await message.reply("ℹ️ No automatic fixes available for these issues.")
        
        # Handle keyboard button: Stats
        @dp.message(F.text == "📊 Stats")
        async def btn_stats(message: Message):
            code, language = self._extract_code(message)
            
            if not code and message.from_user:
                user_id = message.from_user.id
                if user_id in self._user_files:
                    stored = self._user_files[user_id]
                    code = stored["content"]
                    language = stored["language"]
            
            if not code:
                await message.reply("📝 Send code to get statistics.")
                return
            
            result = self.analyzer.analyze_code(code, language)
            
            response = f"""📊 <b>Code Statistics</b>

<b>Language:</b> {result.language}
<b>Lines:</b> {result.lines_analyzed}
<b>Score:</b> {result.score}/100
<b>Issues:</b> {len(result.issues)}

<b>Summary:</b>
{result.summary}"""
            await message.reply(response, reply_markup=get_main_keyboard())
        
        # Handle keyboard button: Analyze
        @dp.message(F.text == "📈 Analyze")
        async def btn_analyze(message: Message):
            code, language = self._extract_code(message)
            
            if not code and message.from_user:
                user_id = message.from_user.id
                if user_id in self._user_files:
                    stored = self._user_files[user_id]
                    code = stored["content"]
                    language = stored["language"]
            
            if not code:
                await message.reply("📝 Send code to analyze.")
                return
            
            result = self.analyzer.analyze_code(code, language)
            
            score_emoji = "🟢" if result.score >= 90 else "🟡" if result.score >= 70 else "🟠" if result.score >= 50 else "🔴"
            
            response = f"""📈 <b>Quick Analysis</b>

{score_emoji} <b>Score: {result.score}/100</b>

<b>Language:</b> {result.language}
<b>Lines:</b> {result.lines_analyzed}
<b>Issues:</b> {len(result.issues)}

{result.summary}"""
            await message.reply(response, reply_markup=get_main_keyboard())
        
        # Handle keyboard button: Upload
        @dp.message(F.text == "📎 Upload")
        async def btn_upload(message: Message):
            await message.reply(
                "📎 Send me a code file!\n\n"
                "Supported formats:\n"
                ".py .js .ts .jsx .tsx .java .go .rs .c .cpp .cs",
                reply_markup=get_main_keyboard()
            )
        
        # Handle keyboard button: Chat (Smart Code Conversation)
        @dp.message(F.text == "💬 Chat")
        async def btn_chat(message: Message):
            text = """
💬 <b>Smart Code Chat</b>

Send me code and ask questions!

<b>Examples:</b>
1. Send code + "این تابع چیکار میکنه؟"
2. Send code + "چطور بهترش کنم؟"
3. Send code + "باگ کجاست؟"

<b>Or ask me to explain:</b>
"این کد رو توضیح بده"

Ready to chat! 💡
"""
            await message.reply(text, reply_markup=get_main_keyboard())
        
        # Handle keyboard button: Translate
        @dp.message(F.text == "🌍 Translate")
        async def btn_translate(message: Message):
            text = """
🌍 <b>Code Translation</b>

Send code and I'll translate it!

<b>Examples:</b>
1. "Python to JavaScript" + کد
2. "Java to Python" + کد
3. "C++ to Go" + کد

<b>Supported:</b>
Python ↔ JavaScript ↔ Java ↔ Go ↔ C++ ↔ Rust

Send your code now! 🔄
"""
            await message.reply(text, reply_markup=get_main_keyboard())
        
        # Handle keyboard button: Write (Generate Code)
        @dp.message(F.text == "✍️ Write")
        async def btn_write(message: Message):
            text = """
✍️ <b>Write Code for Me</b>

Describe what you need in Persian!

<b>Examples:</b>
1. "یک کد بنویس که hello چاپ کنه"
2. "یک تابع بنویس که عدد فیبوناچی برگردونه"
3. "یک برنامه ماشین حساب بنویس"

<b>Languages:</b>
Python, JavaScript, Java, C++, Go, Rust

Type your request! 💻
"""
            await message.reply(text, reply_markup=get_main_keyboard())
        
        # Handle keyboard button: AI
        @dp.message(F.text == "🤖 AI")
        async def btn_ai(message: Message):
            text = """
🤖 <b>AI-Powered Analysis</b>

Send code and get AI insights!

<b>Features:</b>
1. 🔍 <b>AI Review</b> - Deep code analysis
2. 📖 <b>AI Explain</b> - Detailed explanation
3. 💡 <b>AI Suggest</b> - Improvement suggestions
4. ✍️ <b>AI Generate</b> - Generate from description

<b>How to use:</b>
1. Send code + "AI بررسی کن"
2. Send code + "AI توضیح بده"
3. Send code + "AI پیشنهاد بده"
4. "AI بنویس که..."

<b>Note:</b> Requires OpenAI API key configured.
"""
            await message.reply(text, reply_markup=get_main_keyboard())
        
        # Handle keyboard button: Help
        @dp.message(F.text == "❓ Help")
        async def btn_help(message: Message):
            text = """
🛡️ <b>CodeSentinel Bot</b>

AI-powered code review at your fingertips!

<b>Keyboard Buttons:</b>
🔍 Review - Review code or file
🔧 Fix - Auto-fix issues
📊 Stats - Code statistics
📈 Analyze - Quick analysis
💬 Chat - Smart code conversation
🌍 Translate - Code translation
✍️ Write - Generate code from Persian
📎 Upload - Upload a file
❓ Help - This help message

<b>Commands:</b>
/review - Review code
/analyze - Quick analysis
/fix - Auto-fix issues
/stats - Code statistics

<b>Inline Mode:</b>
Type <code>@code_sentinelbot</code> in any chat followed by code!

<b>Supported languages:</b>
Python, JavaScript, TypeScript, Java, Go, Rust, C/C++, and more!
"""
            await message.reply(text, reply_markup=get_main_keyboard())
        
        # Review command
        @dp.message(Command("review"))
        async def cmd_review(message: Message):
            code, language = self._extract_code(message)
            
            # Check for stored file if no code provided
            if not code and message.from_user:
                user_id = message.from_user.id
                if user_id in self._user_files:
                    stored = self._user_files[user_id]
                    code = stored["content"]
                    language = stored["language"]
                    await message.reply(f"📄 Reviewing stored file: {stored['name']}")
            
            if not code:
                await message.reply(
                    "📝 Send code to review:\n\n"
                    "1. Type code directly\n"
                    "2. Upload a file\n"
                    "3. Send code block with ```"
                )
                return
            
            result = self.analyzer.analyze_code(code, language)
            
            response = f"""🔍 <b>Code Review</b>

{self._format_result(result)}

💡 <b>Tip:</b> Use buttons below for more actions!"""
            await message.reply(response, reply_markup=get_main_keyboard())
        
        # Analyze command
        @dp.message(Command("analyze"))
        async def cmd_analyze(message: Message):
            code, language = self._extract_code(message)
            
            if not code and message.from_user:
                user_id = message.from_user.id
                if user_id in self._user_files:
                    stored = self._user_files[user_id]
                    code = stored["content"]
                    language = stored["language"]
            
            if not code:
                await message.reply("📝 Send code to analyze.")
                return
            
            result = self.analyzer.analyze_code(code, language)
            
            score_emoji = "🟢" if result.score >= 90 else "🟡" if result.score >= 70 else "🟠" if result.score >= 50 else "🔴"
            
            response = f"""📈 <b>Quick Analysis</b>

{score_emoji} <b>Score: {result.score}/100</b>

<b>Language:</b> {result.language}
<b>Lines:</b> {result.lines_analyzed}
<b>Issues:</b> {len(result.issues)}

{result.summary}"""
            await message.reply(response, reply_markup=get_main_keyboard())
        
        # Fix command
        @dp.message(Command("fix"))
        async def cmd_fix(message: Message):
            code, language = self._extract_code(message)
            
            if not code and message.from_user:
                user_id = message.from_user.id
                if user_id in self._user_files:
                    stored = self._user_files[user_id]
                    code = stored["content"]
                    language = stored["language"]
            
            if not code:
                await message.reply("📝 Send code to fix.")
                return
            
            result = self.analyzer.analyze_code(code, language)
            
            if not result.issues:
                await message.reply("✅ No issues found! Code looks good.")
                return
            
            fixed_code, changes = self.fixer.fix(code, result.issues)
            
            if changes:
                response = f"""🔧 <b>Fixed Code:</b>

<code>{self._escape_html(fixed_code)}</code>

📝 <b>Changes made:</b>
{chr(10).join(f"• {c}" for c in changes[:5])}

💡 <b>Tip:</b> Review the changes before using!"""
                await message.reply(response, reply_markup=get_main_keyboard())
            else:
                await message.reply("ℹ️ No automatic fixes available for these issues.")
        
        # Stats command
        @dp.message(Command("stats"))
        async def cmd_stats(message: Message):
            code, language = self._extract_code(message)
            
            if not code and message.from_user:
                user_id = message.from_user.id
                if user_id in self._user_files:
                    stored = self._user_files[user_id]
                    code = stored["content"]
                    language = stored["language"]
            
            if not code:
                await message.reply("📝 Send code to get statistics.")
                return
            
            result = self.analyzer.analyze_code(code, language)
            
            response = f"""📊 <b>Code Statistics</b>

<b>Language:</b> {result.language}
<b>Lines:</b> {result.lines_analyzed}
<b>Score:</b> {result.score}/100
<b>Issues:</b> {len(result.issues)}

<b>Summary:</b>
{result.summary}"""
            await message.reply(response, reply_markup=get_main_keyboard())
        
        # Handle file uploads
        @dp.message(F.document)
        async def handle_document(message: Message):
            if not message.document:
                return
            
            # Check if it's a code file
            file_name = message.document.file_name or ""
            file_ext = Path(file_name).suffix.lower()
            
            supported_extensions = [
                ".py", ".js", ".ts", ".jsx", ".tsx", 
                ".java", ".go", ".rs", ".c", ".cpp", ".cs",
                ".rb", ".php", ".swift", ".kt",
            ]
            
            if file_ext not in supported_extensions:
                await message.reply(
                    f"❌ Unsupported file type: {file_ext}\n\n"
                    "Supported: " + ", ".join(supported_extensions)
                )
                return
            
            # Download file
            await message.reply("📥 Downloading file...")
            
            file = await self._bot.get_file(message.document.file_id)
            file_path = f"/tmp/{file_name}"
            await self._bot.download_file(file.file_path, file_path)
            
            # Read and analyze
            try:
                content = Path(file_path).read_text(encoding="utf-8")
                language = self._detect_language(file_ext)
                
                # Store file for user
                if message.from_user:
                    self._user_files[message.from_user.id] = {
                        "name": message.document.file_name,
                        "content": content,
                        "language": language,
                    }
                
                result = self.analyzer.analyze_code(content, language)
                
                response = f"""📄 <b>File Review: {message.document.file_name}</b>

{self._format_result(result)}

💡 <b>Tip:</b> Use buttons below for more actions!"""
                await message.reply(response, reply_markup=get_main_keyboard())
            except Exception as e:
                await message.reply(f"❌ Error reading file: {e}")
            finally:
                # Cleanup
                Path(file_path).unlink(missing_ok=True)
        
        # Handle code blocks
        @dp.message(F.text.contains("```"))
        async def handle_code_block(message: Message):
            """Auto-analyze code blocks."""
            code, language = self._extract_code(message)
            
            if code:
                result = self.analyzer.analyze_code(code, language)
                
                response = f"""🔍 <b>Code Detected</b>

{self._format_result(result)}

<b>Tip:</b> Use buttons below for more actions!"""
                await message.reply(response, reply_markup=get_main_keyboard())
        
        # Catch-all handler for Persian requests (MUST BE LAST)
        @dp.message()
        async def handle_any_message(message: Message):
            """Handle any unmatched message - check for Persian keywords."""
            text = message.text or ""
            
            # Skip if it's a command
            if text.startswith("/"):
                return
            
            # Skip keyboard buttons
            keyboard_buttons = ["🔍 Review", "🔧 Fix", "📊 Stats", "📈 Analyze", "📎 Upload", "❓ Help", "💬 Chat", "🌍 Translate", "✍️ Write", "🤖 AI"]
            if text in keyboard_buttons:
                return
            
            # Check for AI requests first
            ai_keywords = ["AI بررسی", "AI توضیح", "AI پیشنهاد", "AI بنویس", "ai review", "ai explain", "ai suggest", "ai generate"]
            if any(keyword.lower() in text.lower() for keyword in ai_keywords):
                try:
                    # Extract code if present
                    code, language = self._extract_code(message)
                    
                    if "AI بررسی" in text or "ai review" in text.lower():
                        if code:
                            await message.reply("🤖 <b>AI Analyzing...</b>\n\nPlease wait...")
                            result = await self.ai_provider.analyze_code(code, language)
                            if result["success"]:
                                response = f"""🤖 <b>AI Analysis:</b>

{result['analysis']}"""
                                await message.reply(response, reply_markup=get_main_keyboard())
                            else:
                                await message.reply(f"❌ AI Error: {result['error']}", reply_markup=get_main_keyboard())
                        else:
                            await message.reply("📝 Send code with 'AI بررسی' to analyze.", reply_markup=get_main_keyboard())
                        return
                    
                    elif "AI توضیح" in text or "ai explain" in text.lower():
                        if code:
                            await message.reply("🤖 <b>AI Explaining...</b>\n\nPlease wait...")
                            result = await self.ai_provider.explain_code(code, language)
                            if result["success"]:
                                response = f"""📖 <b>AI Explanation:</b>

{result['explanation']}"""
                                await message.reply(response, reply_markup=get_main_keyboard())
                            else:
                                await message.reply(f"❌ AI Error: {result['error']}", reply_markup=get_main_keyboard())
                        else:
                            await message.reply("📝 Send code with 'AI توضیح' to explain.", reply_markup=get_main_keyboard())
                        return
                    
                    elif "AI پیشنهاد" in text or "ai suggest" in text.lower():
                        if code:
                            await message.reply("🤖 <b>AI Suggesting...</b>\n\nPlease wait...")
                            result = await self.ai_provider.suggest_improvements(code, language)
                            if result["success"]:
                                response = f"""💡 <b>AI Suggestions:</b>

{result['suggestions']}"""
                                await message.reply(response, reply_markup=get_main_keyboard())
                            else:
                                await message.reply(f"❌ AI Error: {result['error']}", reply_markup=get_main_keyboard())
                        else:
                            await message.reply("📝 Send code with 'AI پیشنهاد' to get suggestions.", reply_markup=get_main_keyboard())
                        return
                    
                    elif "AI بنویس" in text or "ai generate" in text.lower():
                        # Extract description after "AI بنویس"
                        description = text.replace("AI بنویس", "").replace("ai generate", "").strip()
                        if not description:
                            await message.reply("📝 Add description after 'AI بنویس'\n\nExample: AI بنویس که hello چاپ کنه", reply_markup=get_main_keyboard())
                            return
                        
                        # Detect language
                        from .ai_features import detect_language
                        lang = detect_language(text)
                        
                        await message.reply("🤖 <b>AI Generating...</b>\n\nPlease wait...")
                        result = await self.ai_provider.generate_code(description, lang)
                        if result["success"]:
                            response = f"""✍️ <b>AI Generated Code ({lang.title()}):</b>

<code>{self._escape_html(result['code'])}</code>

💡 <b>Tip:</b> Copy and use this code!"""
                            await message.reply(response, reply_markup=get_main_keyboard())
                        else:
                            await message.reply(f"❌ AI Error: {result['error']}", reply_markup=get_main_keyboard())
                        return
                
                except Exception as e:
                    print(f"Error in AI handler: {e}")
                    await message.reply(
                        "❌ Error processing AI request. Please try again.",
                        reply_markup=get_main_keyboard()
                    )
            
            # Check for Persian code generation keywords
            persian_keywords = ["بنویس", "بساز", "کد", "چاپ", "سلام دنیا", "hello", "توضیح", "ترجمه", "ماشین حساب", "فیبوناچی", "لیست", "حلقه", "شرط", "کلاس", "رندوم", "عدد", "تاریخ", "زمان", "فایل", "اتصال"]
            
            if any(keyword in text for keyword in persian_keywords):
                try:
                    # Detect language
                    from .ai_features import detect_language, generate_code_from_persian, explain_code, translate_code
                    lang = detect_language(text)
                    lang_names = {
                        "python": "Python",
                        "c": "C",
                        "cpp": "C++",
                        "javascript": "JavaScript",
                        "java": "Java",
                        "go": "Go",
                        "rust": "Rust",
                    }
                    lang_name = lang_names.get(lang, "Python")
                    
                    # Check for code generation request
                    if any(word in text for word in ["بنویس", "بساز", "کد"]):
                        code = generate_code_from_persian(text)
                        if code:
                            response = f"""✍️ <b>Generated Code ({lang_name}):</b>

<code>{self._escape_html(code)}</code>

💡 <b>Tip:</b> Copy and use this code!"""
                            await message.reply(response, reply_markup=get_main_keyboard())
                            return
                    
                    # Check for code explanation request
                    if "توضیح" in text:
                        code, _ = self._extract_code(message)
                        if code:
                            explanation = explain_code(code)
                            response = f"""📖 <b>Code Explanation:</b>

{explanation}"""
                            await message.reply(response, reply_markup=get_main_keyboard())
                            return
                        else:
                            await message.reply(
                                "📝 Send code and I'll explain it!\n\n"
                                "Example:\n"
                                "<code>def hello():\n    print('Hi')</code>\n"
                                "+ توضیح بده",
                                reply_markup=get_main_keyboard()
                            )
                            return
                    
                    # Check for translation request
                    if "ترجمه" in text:
                        code, _ = self._extract_code(message)
                        if code:
                            target = "javascript"
                            if "java" in text.lower():
                                target = "java"
                            elif "python" in text.lower():
                                target = "python"
                            
                            translated = translate_code(code, target)
                            response = f"""🌍 <b>Translated to {target.title()}:</b>

<code>{self._escape_html(translated)}</code>

💡 <b>Tip:</b> Copy and use this code!"""
                            await message.reply(response, reply_markup=get_main_keyboard())
                            return
                        else:
                            await message.reply(
                                "📝 Send code and specify target language!\n\n"
                                "Example:\n"
                                "<code>def hello():\n    print('Hi')</code>\n"
                                "+ ترجمه به JavaScript",
                                reply_markup=get_main_keyboard()
                            )
                            return
                    
                    # Default: try to generate code
                    code = generate_code_from_persian(text)
                    if code:
                        response = f"""✍️ <b>Generated Code ({lang_name}):</b>

<code>{self._escape_html(code)}</code>

💡 <b>Tip:</b> Copy and use this code!"""
                        await message.reply(response, reply_markup=get_main_keyboard())
                except Exception as e:
                    print(f"Error in Persian handler: {e}")
                    await message.reply(
                        "❌ Error processing request. Please try again.",
                        reply_markup=get_main_keyboard()
                    )
        
        # ========== INLINE QUERY HANDLER ==========
        @dp.inline_query()
        async def handle_inline_query(inline_query: InlineQuery):
            """Handle inline queries like @code_sentinelbot code"""
            query = inline_query.query.strip()
            
            if not query:
                # Show help when empty
                results = [
                    InlineQueryResultArticle(
                        id="help",
                        title="📖 How to use CodeSentinel",
                        description="Type code after @code_sentinelbot to analyze it",
                        input_message_content=InputTextMessageContent(
                            message_text="🛡️ <b>CodeSentinel Inline Mode</b>\n\nType code after the bot name to analyze it!\n\nExample: <code>@code_sentinelbot print('hello')</code>",
                        ),
                    )
                ]
                await inline_query.answer(results, cache_time=1)
                return
            
            # Analyze the code
            result = self.analyzer.analyze_code(query, "python")
            
            # Format response
            score_emoji = "🟢" if result.score >= 90 else "🟡" if result.score >= 70 else "🟠" if result.score >= 50 else "🔴"
            
            message_text = f"""
{score_emoji} <b>Score: {result.score:.1f}/100</b>

{result.summary}

<b>Language:</b> {result.language}
<b>Lines:</b> {result.lines_analyzed}
"""
            
            # Add issues if any
            if result.issues:
                message_text += "\n<b>Issues:</b>\n"
                for issue in result.issues[:5]:
                    severity_emoji = {"critical": "🔥", "error": "❌", "warning": "⚠️", "info": "ℹ️"}
                    emoji = severity_emoji.get(issue.severity.value, "•")
                    message_text += f"{emoji} Line {issue.line}: {issue.message}\n"
            
            results = [
                InlineQueryResultArticle(
                    id="review",
                    title=f"🔍 Review: {query[:30]}...",
                    description=f"Score: {result.score:.1f}/100 | {result.summary}",
                    input_message_content=InputTextMessageContent(
                        message_text=message_text,
                    ),
                )
            ]
            
            await inline_query.answer(results, cache_time=0)
    
    def _extract_code(self, message) -> tuple[str, str]:
        """Extract code from message."""
        text = message.text or message.caption or ""
        
        # Check for code block
        if "```" in text:
            parts = text.split("```")
            if len(parts) >= 3:
                code = parts[1].strip()
                # Check for language hint
                first_line = code.split("\n")[0]
                if first_line and not first_line.startswith((".", "-", "#")):
                    language = first_line
                    code = "\n".join(code.split("\n")[1:])
                else:
                    language = "python"
                return code, language
        
        # Check for file attachment
        if message.document:
            # Will be handled by document handler
            return "", ""
        
        # Handle commands with code (e.g., /fix Print("heel"))
        if text.startswith("/"):
            # Extract code after command
            parts = text.split(maxsplit=1)
            if len(parts) > 1:
                code = parts[1].strip()
                if code:
                    return code, "python"
            return "", ""
        
        # Handle keyboard button presses (ignore them)
        if text in ["🔍 Review", "🔧 Fix", "📊 Stats", "📈 Analyze", "📎 Upload", "❓ Help", "💬 Chat", "🌍 Translate", "✍️ Write", "🤖 AI"]:
            return "", ""
        
        # Plain text code (not a command)
        if text:
            return text, "python"
        
        return "", ""
    
    def _detect_language(self, ext: str) -> str:
        """Detect language from extension."""
        ext_map = {
            ".py": "python",
            ".js": "javascript",
            ".jsx": "javascript",
            ".ts": "typescript",
            ".tsx": "typescript",
            ".java": "java",
            ".go": "go",
            ".rs": "rust",
            ".c": "c",
            ".cpp": "cpp",
            ".cs": "csharp",
            ".rb": "ruby",
            ".php": "php",
            ".swift": "swift",
            ".kt": "kotlin",
        }
        return ext_map.get(ext, "python")
    
    def _escape_html(self, text: str) -> str:
        """Escape HTML special characters."""
        return text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
    
    def _format_result(self, result: ReviewResult) -> str:
        """Format review result for display."""
        score_emoji = "🟢" if result.score >= 90 else "🟡" if result.score >= 70 else "🟠" if result.score >= 50 else "🔴"
        
        response = f"""
{score_emoji} <b>Score: {result.score}/100</b>

<b>Language:</b> {result.language}
<b>Lines:</b> {result.lines_analyzed}
"""
        
        if result.issues:
            response += f"\n<b>Issues ({len(result.issues)}):</b>\n"
            for issue in result.issues[:5]:
                severity_emoji = {"critical": "🔥", "error": "❌", "warning": "⚠️", "info": "ℹ️"}
                emoji = severity_emoji.get(issue.severity.value, "•")
                response += f"{emoji} Line {issue.line}: {issue.message}\n"
            
            if len(result.issues) > 5:
                response += f"\n... and {len(result.issues) - 5} more issues"
        else:
            response += "\n✅ No issues found! Code looks good."
        
        return response
    
    def run(self):
        """Run the bot."""
        import asyncio
        
        if not self.token:
            print("❌ Error: No bot token provided!")
            print("Set TELEGRAM_BOT_TOKEN environment variable or pass token to constructor")
            return
        
        print("🛡️ CodeSentinel Bot starting...")
        print(f"Token: {self.token[:10]}...")
        
        self._setup_handlers()
        
        print("✅ Keyboard buttons enabled")
        print("✅ Inline query enabled")
        
        # Start polling
        asyncio.run(self._dispatcher.start_polling(self._bot))


def create_bot(token: Optional[str] = None) -> TelegramBot:
    """Create and return a bot instance."""
    return TelegramBot(token=token)
