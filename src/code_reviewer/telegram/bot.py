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


class TelegramBot:
    """
    Telegram bot for code review.
    
    Supports:
    - Code block analysis
    - File upload review
    - Auto-fix suggestions
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
    
    def _setup_handlers(self):
        """Setup bot command handlers."""
        from aiogram import Bot, Dispatcher, F
        from aiogram.filters import Command
        from aiogram.types import Message, CallbackQuery
        from aiogram.enums import ParseMode
        
        self._bot = Bot(token=self.token, parse_mode=ParseMode.HTML)
        self._dispatcher = Dispatcher()
        
        dp = self._dispatcher
        
        # Help command
        @dp.message(Command("start", "help"))
        async def cmd_help(message: Message):
            text = """
🛡️ <b>CodeSentinel Bot</b>

AI-powered code review at your fingertips!

<b>Commands:</b>
/review - Review code or file
/analyze - Quick code analysis
/fix - Auto-fix issues
/stats - Code statistics
/help - Show this help

<b>How to use:</b>
1. Send a code block with <code>/review</code>
2. Or upload a file and type <code>/review</code>
3. Or just paste code and add <code>/analyze</code>

<b>Supported languages:</b>
Python, JavaScript, TypeScript, Java, Go, Rust, C/C++, and more!
"""
            await message.reply(text)
        
        # Review command
        @dp.message(Command("review"))
        async def cmd_review(message: Message):
            code, language = self._extract_code(message)
            
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
            await message.reply(response, parse_mode=ParseMode.HTML)
        
        # Analyze command (quick)
        @dp.message(Command("analyze"))
        async def cmd_analyze(message: Message):
            code, language = self._extract_code(message)
            
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
            await message.reply(response, parse_mode=ParseMode.HTML)
        
        # Fix command
        @dp.message(Command("fix"))
        async def cmd_fix(message: Message):
            code, language = self._extract_code(message)
            
            if not code:
                await message.reply("📝 Please send code to fix.")
                return
            
            result = self.analyzer.analyze_code(code, language)
            
            if not result.issues:
                await message.reply("✅ No issues found! Code is clean.")
                return
            
            # Apply fixes
            fixed_code = self.fixer.fix(code, result.issues)
            
            if fixed_code == code:
                await message.reply("ℹ️ No auto-fixable issues found.")
                return
            
            response = f"""
🔧 <b>Fixed Code</b>

<b>Original issues:</b> {len(result.issues)}
<b>Score:</b> {self._format_score(result.score)}

<b>Fixed version:</b>
<code>{self._escape_html(fixed_code)}</code>

<b>Note:</b> Review the changes before using!
"""
            await message.reply(response, parse_mode=ParseMode.HTML)
        
        # Stats command
        @dp.message(Command("stats"))
        async def cmd_stats(message: Message):
            code, language = self._extract_code(message)
            
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
            await message.reply(response, parse_mode=ParseMode.HTML)
        
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
                
                result = self.analyzer.analyze_code(content, language)
                
                response = f"""
📄 <b>File Review: {message.document.file_name}</b>

{self._format_result(result)}
"""
                await message.reply(response, parse_mode=ParseMode.HTML)
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

<b>Tip:</b> Use /review for detailed analysis or /fix for auto-fix
"""
                await message.reply(response, parse_mode=ParseMode.HTML)
    
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
        
        # Plain text code
        if text and not text.startswith("/"):
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
