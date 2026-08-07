"""
Git commit message and version control patterns.
"""
import re
from ..core.models import CodeIssue, Severity, IssueCategory
from ..core.rules import BaseRule


class GitCommitRules(BaseRule):
    @property
    def name(self) -> str:
        return "git_commit"
    @property
    def description(self) -> str:
        return "Git commit and version control patterns"
    @property
    def category(self) -> IssueCategory:
        return IssueCategory.BEST_PRACTICE
    @property
    def severity(self) -> Severity:
        return Severity.INFO

    def check(self, file_path: str, content: str) -> list[CodeIssue]:
        issues = []
        lines = content.splitlines()
        patterns = [
            # Git commands
            (r"git\s+init|git\s+clone|git\s+add|git\s+commit|git\s+push|git\s+pull|git\s+fetch|git\s+merge|git\s+rebase|git\s+branch|git\s+checkout|git\s+switch|git\s+stash|git\s+tag|git\s+log|git\s+diff|git\s+status|git\s+remote|git\s+reset|git\s+revert|git\s+cherry-pick|git\s+rebase", "Git command", "Good: using Git", Severity.INFO),
            # Branch patterns
            (r"feature/|bugfix/|hotfix/|release/|chore/|docs/|test/|refactor/|perf/|ci/|build/|style/|fix/|update/|add/|remove/|delete/|rename/|move/|merge/|revert/", "Branch naming", "Good: branch naming convention", Severity.INFO),
            # Commit conventions
            (r"feat|fix|docs|style|refactor|perf|test|chore|ci|build|revert|init|add|remove|update|delete|rename|move|merge|revert", "Conventional commit", "Good: conventional commit", Severity.INFO),
            # Version tags
            (r"v\d+\.\d+\.\d+|v\d+\.\d+\.\d+-\w+|v\d+\.\d+\.\d+\+\w+", "Semantic version", "Good: semantic versioning", Severity.INFO),
            # .gitignore patterns
            (r"\.gitignore|\.gitattributes|\.gitmodules|\.gitkeep|\.gitmessage|\.gitconfig|\.gitmodules|\.gitattributes|\.gitignore_global|\.gitignore_global", "Git config files", "Good: git configuration", Severity.INFO),
            # Merge strategies
            (r"merge|Merge|MERGE|rebase|Rebase|REBASE|squash|Squash|SQUASH|fast.?forward|FastForward|fast_forward|no.?fast.?forward|no_fast_forward", "Merge strategy", "Good: merge strategies", Severity.INFO),
            # Git hooks
            (r"pre-commit|pre_push|pre-merge-commit|commit-msg|prepare-commit-msg|post-commit|post-checkout|post-merge|pre-rebase|pre-receive|update|post-receive|post-update|applypatch-msg|sendemail-validate", "Git hook", "Good: git hooks", Severity.INFO),
            # Git tools
            (r"gh|hub|lazygit|tig|gitk|gitui|git-cola|git-gui|gitKraken|SourceTree|sourcetree|Fork|fork|GitLens|gitlens|GitTower|gittower|Sublime Merge|sublime.merge", "Git tool", "Good: git tools", Severity.INFO),
            # Git aliases
            (r"git\s+co|git\s+ci|git\s+st|git\s+br|git\s+df|git\s+lg|git\s+last|git\s+unstage|git\s+uncommit|git\s+amend|git\s+undo|git\s+prune|git\s+clean", "Git alias", "Good: git aliases", Severity.INFO),
            # Git strategies
            (r"feature.?branch|feature_branch|git.?flow|git_flow|trunk.?based|trunk_based|github.?flow|github_flow|gitlab.?flow|gitlab_flow|one.?branch|one_branch|monorepo|monorepo", "Git strategy", "Good: git strategies", Severity.INFO),
            # Conflict resolution
            (r"conflict|Conflict|CONFLICT|merge.?conflict|merge_conflict|resolution|Resolution|RESOLUTION", "Merge conflict", "Resolve merge conflicts", Severity.WARNING),
            # Stashing
            (r"stash|Stash|STASH|stash@|stash push|stash pop|stash apply|stash drop|stash list|stash show|stash clear|stash branch", "Git stash", "Good: git stashing", Severity.INFO),
            # Cherry-pick
            (r"cherry.?pick|cherry_pick|CherryPick", "Cherry pick", "Good: cherry picking", Severity.INFO),
            # Bisect
            (r"bisect|Bisect|BISECT|git bisect start|git bisect good|git bisect bad", "Git bisect", "Good: git bisect", Severity.INFO),
            # Worktrees
            (r"worktree|Worktree|WORKTREE|git worktree add|git worktree list|git worktree remove|git worktree move", "Git worktree", "Good: git worktrees", Severity.INFO),
            # Submodules
            (r"submodule|Submodule|SUBMODULE|git submodule add|git submodule update|git submodule init|git submodule deinit|git submodule sync", "Git submodule", "Good: git submodules", Severity.INFO),
            # Worktrees
            (r"worktree|Worktree|WORKTREE|git worktree add|git worktree list|git worktree remove|git worktree move", "Git worktree", "Good: git worktrees", Severity.INFO),
            # Submodules
            (r"submodule|Submodule|SUBMODULE|git submodule add|git submodule update|git submodule init|git submodule deinit|git submodule sync", "Git submodule", "Good: git submodules", Severity.INFO),
        ]
        for line_num, line in enumerate(lines, 1):
            stripped = line.strip()
            if stripped.startswith('#') or stripped.startswith('//'):
                continue
            for pattern, message, severity in patterns:
                if re.search(pattern, line):
                    issues.append(self._create_issue(
                        file_path=file_path, line=line_num, message=message,
                        suggestion=message, severity=severity, code_snippet=stripped,
                    ))
        return issues
