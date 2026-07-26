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


# Main keyboard buttons
MAIN_KEYBOARD = [
    ["🔍 Review", "🔧 Fix"],
    ["📊 Stats", "📈 Analyze"],
    ["💬 Chat", "🌍 Translate"],
    ["✍️ Write", "📎 Upload"],
    ["❓ Help"],
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
    - Group and private chats
    
    Example:
        bot = TelegramBot(token="YOUR_BOT_TOKEN")
        bot.run()
    """
    
    def __init__(self, token: Optional[str] = None):
        self.token = token or os.getenv("TELEGRAM_BOT_TOKEN", "")
        self.analyzer = CodeAnalyzer()
        self.fixer = AutoFixer()
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
                    [KeyboardButton(text="✍️ Write"), KeyboardButton(text="📎 Upload")],
                    [KeyboardButton(text="❓ Help")],
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
1. Send code or upload a file
2. Use buttons below for quick actions
3. Or use inline mode in any chat: <code>@code_sentinelbot your_code</code>

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
            
            await message.reply("🔍 Analyzing code...")
            result = self.analyzer.analyze_code(code, language)
            response = self._format_result(result)
            await message.reply(response, reply_markup=get_main_keyboard())
        
        # Handle keyboard button: Fix
        @dp.message(F.text == "🔧 Fix")
        async def btn_fix(message: Message):
            code, language = self._extract_code(message)
            
            # Check for stored file
            if not code and message.from_user:
                user_id = message.from_user.id
                if user_id in self._user_files:
                    stored = self._user_files[user_id]
                    code = stored["content"]
                    language = stored["language"]
                    await message.reply(f"📄 Fixing stored file: {stored['name']}")
            
            if not code:
                await message.reply("📝 Send code to fix.")
                return
            
            result = self.analyzer.analyze_code(code, language)
            
            if not result.issues:
                await message.reply(
                    "✅ No issues found! Code is clean.",
                    reply_markup=get_main_keyboard()
                )
                return
            
            fixed_code = self.fixer.fix(code, result.issues)
            
            if fixed_code == code:
                await message.reply(
                    "ℹ️ No auto-fixable issues found.",
                    reply_markup=get_main_keyboard()
                )
                return
            
            response = f"""
🔧 <b>Fixed Code</b>

<b>Issues found:</b> {len(result.issues)}
<b>Score:</b> {self._format_score(result.score)}

<b>Fixed version:</b>
<code>{self._escape_html(fixed_code)}</code>

<b>⚠️ Review before using!</b>
"""
            await message.reply(response, reply_markup=get_main_keyboard())
        
        # Handle keyboard button: Stats
        @dp.message(F.text == "📊 Stats")
        async def btn_stats(message: Message):
            code, language = self._extract_code(message)
            
            # Check for stored file
            if not code and message.from_user:
                user_id = message.from_user.id
                if user_id in self._user_files:
                    stored = self._user_files[user_id]
                    code = stored["content"]
                    language = stored["language"]
            
            if not code:
                await message.reply("📝 Send code for statistics.")
                return
            
            result = self.analyzer.analyze_code(code, language)
            
            lines = code.splitlines()
            blank_lines = len([l for l in lines if not l.strip()])
            comment_lines = len([l for l in lines if l.strip().startswith('#') or l.strip().startswith('//')])
            code_lines = len(lines) - blank_lines - comment_lines
            
            response = f"""
📊 <b>Code Statistics</b>

<b>Language:</b> {result.language}
<b>Total lines:</b> {len(lines)}
<b>Code lines:</b> {code_lines}
<b>Comments:</b> {comment_lines}
<b>Blank lines:</b> {blank_lines}

<b>Quality:</b>
Score: {self._format_score(result.score)}
Issues: {len(result.issues)}
"""
            await message.reply(response, reply_markup=get_main_keyboard())
        
        # Handle keyboard button: Analyze
        @dp.message(F.text == "📈 Analyze")
        async def btn_analyze(message: Message):
            code, language = self._extract_code(message)
            
            # Check for stored file
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
            
            response = f"""
🛡️ <b>Quick Analysis</b>

Score: {self._format_score(result.score)}
Language: {result.language}
Lines: {result.lines_analyzed}

{result.summary}
"""
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
                    "📝 Please send code to review.\n\n"
                    "Options:\n"
                    "1. Send a code block: <code>/review</code>\n"
                    "2. Upload a file and type <code>/review</code>"
                )
                return
            
            await message.reply("🔍 Analyzing code...")
            
            result = self.analyzer.analyze_code(code, language)
            
            response = self._format_result(result)
            await message.reply(response, reply_markup=get_main_keyboard())
        
        # Analyze command (quick)
        @dp.message(Command("analyze"))
        async def cmd_analyze(message: Message):
            code, language = self._extract_code(message)
            
            # Check for stored file if no code provided
            if not code and message.from_user:
                user_id = message.from_user.id
                if user_id in self._user_files:
                    stored = self._user_files[user_id]
                    code = stored["content"]
                    language = stored["language"]
            
            if not code:
                await message.reply("📝 Please send code to analyze.")
                return
            
            result = self.analyzer.analyze_code(code, language)
            
            # Quick summary
            response = f"""
🛡️ <b>Quick Analysis</b>

Score: {self._format_score(result.score)}
Language: {result.language}
Lines: {result.lines_analyzed}

{result.summary}
"""
            await message.reply(response, reply_markup=get_main_keyboard())
        
        # Fix command
        @dp.message(Command("fix"))
        async def cmd_fix(message: Message):
            code, language = self._extract_code(message)
            
            # Check for stored file if no code provided
            if not code and message.from_user:
                user_id = message.from_user.id
                if user_id in self._user_files:
                    stored = self._user_files[user_id]
                    code = stored["content"]
                    language = stored["language"]
                    await message.reply(f"📄 Fixing stored file: {stored['name']}")
            
            if not code:
                await message.reply("📝 Please send code to fix.")
                return
            
            result = self.analyzer.analyze_code(code, language)
            
            if not result.issues:
                await message.reply(
                    "✅ No issues found! Code is clean.",
                    reply_markup=get_main_keyboard()
                )
                return
            
            # Apply fixes
            fixed_code = self.fixer.fix(code, result.issues)
            
            if fixed_code == code:
                await message.reply(
                    "ℹ️ No auto-fixable issues found.",
                    reply_markup=get_main_keyboard()
                )
                return
            
            response = f"""
🔧 <b>Fixed Code</b>

<b>Original issues:</b> {len(result.issues)}
<b>Score:</b> {self._format_score(result.score)}

<b>Fixed version:</b>
<code>{self._escape_html(fixed_code)}</code>

<b>Note:</b> Review the changes before using!
"""
            await message.reply(response, reply_markup=get_main_keyboard())
        
        # Stats command
        @dp.message(Command("stats"))
        async def cmd_stats(message: Message):
            code, language = self._extract_code(message)
            
            # Check for stored file if no code provided
            if not code and message.from_user:
                user_id = message.from_user.id
                if user_id in self._user_files:
                    stored = self._user_files[user_id]
                    code = stored["content"]
                    language = stored["language"]
            
            if not code:
                await message.reply("📝 Please send code for statistics.")
                return
            
            result = self.analyzer.analyze_code(code, language)
            
            # Calculate metrics
            lines = code.splitlines()
            blank_lines = len([l for l in lines if not l.strip()])
            comment_lines = len([l for l in lines if l.strip().startswith('#') or l.strip().startswith('//')])
            code_lines = len(lines) - blank_lines - comment_lines
            
            response = f"""
📊 <b>Code Statistics</b>

<b>Language:</b> {result.language}
<b>Total lines:</b> {len(lines)}
<b>Code lines:</b> {code_lines}
<b>Comments:</b> {comment_lines}
<b>Blank lines:</b> {blank_lines}

<b>Quality:</b>
Score: {self._format_score(result.score)}
Issues: {len(result.issues)}
"""
            await message.reply(response, reply_markup=get_main_keyboard())
        
        # Handle file uploads
        @dp.message(F.document)
        async def handle_document(message: Message):
            if not message.document:
                return
            
            # Check if it's a code file
            supported_exts = {'.py', '.js', '.ts', '.jsx', '.tsx', '.java', '.go', '.rs', '.c', '.cpp', '.cs'}
            file_ext = Path(message.document.file_name or "").suffix.lower()
            
            if file_ext not in supported_exts:
                await message.reply(
                    f"⚠️ Unsupported file type: {file_ext}\n\n"
                    f"Supported: {', '.join(supported_exts)}"
                )
                return
            
            await message.reply("📥 Downloading file...")
            
            # Download file
            file = await self._bot.get_file(message.document.file_id)
            file_path = f"/tmp/{message.document.file_name}"
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
                
                response = f"""
📄 <b>File Review: {message.document.file_name}</b>

{self._format_result(result)}

💡 <b>Tip:</b> Use buttons below for more actions!
"""
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
                
                response = f"""
🔍 <b>Code Detected</b>

{self._format_result(result)}

<b>Tip:</b> Use buttons below for more actions!
"""
                await message.reply(response, reply_markup=get_main_keyboard())
        
        # Handle Persian code generation requests
        @dp.message(F.text.contains("بنویس") | F.text.contains("بساز") | F.text.contains("کد") | F.text.contains("چاپ") | F.text.contains("سلام دنیا") | F.text.contains("hello") | F.text.contains("توضیح") | F.text.contains("ترجمه"))
        async def handle_persian_request(message: Message):
            text = message.text or ""
            
            # Check for code generation request
            if any(word in text for word in ["بنویس", "بساز", "کد"]):
                # Detect language
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
                
                code = generate_code_from_persian(text)
                if code:
                    response = f"""✍️ <b>Generated Code ({lang_name}):</b>

<code>{self._escape_html(code)}</code>

💡 <b>Tip:</b> Copy and use this code!"""
                    await message.reply(response, reply_markup=get_main_keyboard())
                    return
            
            # Check for code explanation request
            if "توضیح" in text:
                # Try to extract code from message
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
                    # Detect target language
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
                response = f"""✍️ <b>Generated Code:</b>

<code>{self._escape_html(code)}</code>

💡 <b>Tip:</b> Copy and use this code!"""
                await message.reply(response, reply_markup=get_main_keyboard())
        
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
        if text in ["🔍 Review", "🔧 Fix", "📊 Stats", "📈 Analyze", "📎 Upload", "❓ Help", "💬 Chat", "🌍 Translate", "✍️ Write"]:
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
            ".ts": "typescript",
            ".jsx": "javascript",
            ".tsx": "typescript",
            ".java": "java",
            ".go": "go",
            ".rs": "rust",
            ".c": "c",
            ".cpp": "cpp",
            ".cs": "csharp",
        }
        return ext_map.get(ext, "unknown")
    
    def _format_result(self, result: ReviewResult) -> str:
        """Format review result for Telegram."""
        lines = []
        
        # Score
        lines.append(f"Score: {self._format_score(result.score)}")
        lines.append(f"Language: {result.language}")
        lines.append(f"Lines: {result.lines_analyzed}")
        lines.append("")
        
        # Summary
        lines.append(f"<b>{result.summary}</b>")
        lines.append("")
        
        # Issues (limited to 10)
        if result.issues:
            lines.append("<b>Issues:</b>")
            for issue in result.issues[:10]:
                severity_emoji = {
                    Severity.CRITICAL: "🔥",
                    Severity.ERROR: "❌",
                    Severity.WARNING: "⚠️",
                    Severity.INFO: "ℹ️",
                }
                emoji = severity_emoji.get(issue.severity, "•")
                lines.append(f"{emoji} <code>Line {issue.line}</code>: {issue.message}")
            
            if len(result.issues) > 10:
                lines.append(f"\n... and {len(result.issues) - 10} more issues")
        
        return "\n".join(lines)
    
    def _format_score(self, score: float) -> str:
        """Format score with emoji."""
        if score >= 90:
            return f"🟢 {score:.1f}/100"
        elif score >= 70:
            return f"🟡 {score:.1f}/100"
        elif score >= 50:
            return f"🟠 {score:.1f}/100"
        else:
            return f"🔴 {score:.1f}/100"
    
    def _escape_html(self, text: str) -> str:
        """Escape HTML for Telegram."""
        return text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
    
    def run(self):
        """Run the bot."""
        if not self.token:
            raise ValueError(
                "Telegram bot token not found!\n"
                "Set TELEGRAM_BOT_TOKEN environment variable or pass token to constructor."
            )
        
        self._setup_handlers()
        
        print("🛡️ CodeSentinel Bot starting...")
        print("✅ Keyboard buttons enabled")
        print("✅ Inline query enabled")
        asyncio.run(self._dispatcher.start_polling(self._bot))
    
    async def send_review(self, chat_id: int, code: str, language: str = "python"):
        """Send review to a specific chat."""
        if not self._bot:
            from aiogram import Bot
            self._bot = Bot(token=self.token)
        
        result = self.analyzer.analyze_code(code, language)
        response = self._format_result(result)
        
        await self._bot.send_message(chat_id, response, parse_mode="HTML")


def create_bot(token: Optional[str] = None) -> TelegramBot:
    """
    Factory function to create bot.
    
    Args:
        token: Telegram bot token
        
    Returns:
        TelegramBot instance
    """
    return TelegramBot(token=token)
