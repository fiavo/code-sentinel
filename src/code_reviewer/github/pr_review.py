"""
GitHub integration for PR reviews.
"""

import os
from dataclasses import dataclass
from typing import Optional

import httpx

from ..core.analyzer import CodeAnalyzer, AnalyzerConfig
from ..core.models import ReviewResult


@dataclass
class GitHubConfig:
    """GitHub configuration."""
    token: str = ""
    repo: str = ""
    pr_number: int = 0
    
    def __post_init__(self):
        if not self.token:
            self.token = os.getenv("GITHUB_TOKEN", "")


class GitHubPRReviewer:
    """
    Review GitHub Pull Requests.
    
    Example:
        reviewer = GitHubPRReviewer(token="ghp_...")
        result = await reviewer.review_pr("owner/repo", 123)
    """
    
    def __init__(self, token: Optional[str] = None):
        self.token = token or os.getenv("GITHUB_TOKEN", "")
        self.analyzer = CodeAnalyzer()
        self._client = None
    
    async def _get_client(self) -> httpx.AsyncClient:
        """Get or create HTTP client."""
        if self._client is None:
            self._client = httpx.AsyncClient(
                base_url="https://api.github.com",
                headers={
                    "Authorization": f"token {self.token}",
                    "Accept": "application/vnd.github.v3+json",
                },
                timeout=30.0,
            )
        return self._client
    
    async def review_pr(self, repo: str, pr_number: int) -> ReviewResult:
        """
        Review a GitHub PR.
        
        Args:
            repo: Repository (owner/repo)
            pr_number: PR number
            
        Returns:
            ReviewResult
        """
        client = await self._get_client()
        
        # Get PR files
        response = await client.get(f"/repos/{repo}/pulls/{pr_number}/files")
        response.raise_for_status()
        files = response.json()
        
        all_issues = []
        files_analyzed = 0
        lines_analyzed = 0
        
        for file_info in files:
            filename = file_info["filename"]
            patch = file_info.get("patch", "")
            
            if not patch:
                continue
            
            # Extract new code from patch
            new_lines = []
            for line in patch.split("\n"):
                if line.startswith("+") and not line.startswith("+++"):
                    new_lines.append(line[1:])
            
            if new_lines:
                content = "\n".join(new_lines)
                result = self.analyzer.analyze_code(content, self._detect_language(filename))
                all_issues.extend(result.issues)
                files_analyzed += 1
                lines_analyzed += len(new_lines)
        
        # Calculate score
        score = self._calculate_score(all_issues)
        
        return ReviewResult(
            issues=all_issues,
            score=score,
            summary=self._generate_summary(all_issues),
            files_analyzed=files_analyzed,
            lines_analyzed=lines_analyzed,
        )
    
    async def post_review(self, repo: str, pr_number: int, result: ReviewResult):
        """
        Post review comment on PR.
        
        Args:
            repo: Repository (owner/repo)
            pr_number: PR number
            result: Review result
        """
        client = await self._get_client()
        
        # Create review comment
        body = f"""## 🔍 Code Review Results

**Score: {result.score:.1f}/100**

{result.summary}

### Issues Found
"""
        
        if result.issues:
            for issue in result.issues[:10]:  # Limit to 10 issues
                severity_emoji = {
                    "critical": "🔥",
                    "error": "❌",
                    "warning": "⚠️",
                    "info": "ℹ️",
                }
                emoji = severity_emoji.get(issue.severity.value, "•")
                body += f"- {emoji} **{issue.file}:{issue.line}** - {issue.message}\n"
        else:
            body += "No issues found! ✅\n"
        
        body += f"\n---\n*Powered by AI Code Reviewer*"
        
        # Post review
        response = await client.post(
            f"/repos/{repo}/pulls/{pr_number}/reviews",
            json={
                "body": body,
                "event": "COMMENT",
            },
        )
        response.raise_for_status()
        
        return response.json()
    
    def _detect_language(self, filename: str) -> str:
        """Detect language from filename."""
        ext_map = {
            ".py": "python",
            ".js": "javascript",
            ".ts": "typescript",
            ".java": "java",
            ".go": "go",
            ".rs": "rust",
        }
        
        for ext, lang in ext_map.items():
            if filename.endswith(ext):
                return lang
        
        return "unknown"
    
    def _calculate_score(self, issues: list) -> float:
        """Calculate score from issues."""
        if not issues:
            return 100.0
        
        score = 100.0
        for issue in issues:
            if issue.severity.value == "critical":
                score -= 15
            elif issue.severity.value == "error":
                score -= 10
            elif issue.severity.value == "warning":
                score -= 5
            elif issue.severity.value == "info":
                score -= 1
        
        return max(0.0, score)
    
    def _generate_summary(self, issues: list) -> str:
        """Generate summary."""
        if not issues:
            return "No issues found!"
        
        critical = len([i for i in issues if i.severity.value == "critical"])
        errors = len([i for i in issues if i.severity.value == "error"])
        warnings = len([i for i in issues if i.severity.value == "warning"])
        
        parts = []
        if critical:
            parts.append(f"{critical} critical")
        if errors:
            parts.append(f"{errors} errors")
        if warnings:
            parts.append(f"{warnings} warnings")
        
        return f"Found {', '.join(parts)} issues"
    
    async def close(self):
        """Close HTTP client."""
        if self._client:
            await self._client.aclose()
            self._client = None
