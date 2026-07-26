"""
Auto-fix module for common code issues.
"""

import re
from pathlib import Path
from typing import Optional

from ..core.models import CodeIssue, Severity


class AutoFixer:
    """
    Automatic code fixer for common issues.
    
    Example:
        fixer = AutoFixer()
        fixed_code = fixer.fix(code, issues)
    """
    
    def fix(self, code: str, issues: list[CodeIssue]) -> str:
        """
        Apply auto-fixes to code.
        
        Args:
            code: Original code
            issues: Issues to fix
            
        Returns:
            Fixed code
        """
        lines = code.splitlines()
        
        # Sort issues by line number (descending) to avoid offset issues
        sorted_issues = sorted(issues, key=lambda x: x.line, reverse=True)
        
        for issue in sorted_issues:
            if issue.line < 1 or issue.line > len(lines):
                continue
            
            line_idx = issue.line - 1
            original_line = lines[line_idx]
            
            fixed_line = self._fix_line(original_line, issue)
            if fixed_line != original_line:
                lines[line_idx] = fixed_line
        
        return "\n".join(lines)
    
    def _fix_line(self, line: str, issue: CodeIssue) -> str:
        """Fix a single line based on issue type."""
        rule = issue.rule
        
        # Security fixes
        if rule == "security":
            return self._fix_security(line, issue.message)
        
        # Style fixes
        if rule == "style":
            return self._fix_style(line, issue.message)
        
        # Performance fixes
        if rule == "performance":
            return self._fix_performance(line, issue.message)
        
        return line
    
    def _fix_security(self, line: str, message: str) -> str:
        """Fix security issues."""
        # Trailing whitespace
        if "Trailing whitespace" in message:
            return line.rstrip()
        
        # Hardcoded secrets (add comment)
        if "Hardcoded secret" in message:
            if "=" in line:
                return line + "  # TODO: Use environment variable"
        
        return line
    
    def _fix_style(self, line: str, message: str) -> str:
        """Fix style issues."""
        # Trailing whitespace
        if "Trailing whitespace" in message:
            return line.rstrip()
        
        # Long lines (basic split)
        if "Line too long" in message:
            # Only split simple cases
            if "=" in line and len(line) > 120:
                parts = line.split("=", 1)
                if len(parts) == 2:
                    indent = len(line) - len(line.lstrip())
                    return f"{parts[0].rstrip()} = (\n{' ' * (indent + 4)}{parts[1].strip()}\n{' ' * indent})"
        
        return line
    
    def _fix_performance(self, line: str, message: str) -> str:
        """Fix performance issues."""
        # Bare except
        if "Bare except" in message:
            return line.replace("except:", "except Exception:")
        
        return line
    
    def fix_file(self, file_path: str, issues: list[CodeIssue], dry_run: bool = False) -> dict:
        """
        Fix issues in a file.
        
        Args:
            file_path: Path to file
            issues: Issues to fix
            dry_run: If True, don't write changes
            
        Returns:
            Dictionary with fix results
        """
        path = Path(file_path)
        
        if not path.exists():
            return {"error": f"File not found: {file_path}"}
        
        try:
            content = path.read_text(encoding="utf-8")
        except Exception as e:
            return {"error": f"Could not read file: {e}"}
        
        fixed_content = self.fix(content, issues)
        
        if fixed_content == content:
            return {"fixed": 0, "message": "No changes needed"}
        
        if not dry_run:
            path.write_text(fixed_content, encoding="utf-8")
        
        return {
            "fixed": len(issues),
            "changes": len(content.splitlines()) - len(fixed_content.splitlines()),
        }


class DiffGenerator:
    """Generate diffs for fixed code."""
    
    @staticmethod
    def generate_diff(original: str, fixed: str, file_path: str = "") -> str:
        """
        Generate a unified diff.
        
        Args:
            original: Original code
            fixed: Fixed code
            file_path: File path for header
            
        Returns:
            Unified diff string
        """
        import difflib
        
        original_lines = original.splitlines(keepends=True)
        fixed_lines = fixed.splitlines(keepends=True)
        
        diff = difflib.unified_diff(
            original_lines,
            fixed_lines,
            fromfile=f"a/{file_path}" if file_path else "a/original",
            tofile=f"b/{file_path}" if file_path else "b/fixed",
        )
        
        return "".join(diff)
