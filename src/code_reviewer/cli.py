"""
CLI interface for Code Reviewer.
"""

import asyncio
import sys
from pathlib import Path
from typing import Optional

import click
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.text import Text
from rich.syntax import Syntax
from rich.progress import Progress, SpinnerColumn, TextColumn

from .core.analyzer import CodeAnalyzer, AnalyzerConfig
from .core.models import Severity, ReviewResult
from .ai.provider import create_provider, OpenAIProvider, AIConfig
from .fixers.auto_fix import AutoFixer, DiffGenerator


console = Console()


def format_score(score: float) -> Text:
    """Format score with color."""
    if score >= 90:
        return Text(f"{score:.1f}", style="bold green")
    elif score >= 70:
        return Text(f"{score:.1f}", style="bold yellow")
    elif score >= 50:
        return Text(f"{score:.1f}", style="bold orange")
    else:
        return Text(f"{score:.1f}", style="bold red")


def format_severity(severity: Severity) -> Text:
    """Format severity with color."""
    colors = {
        Severity.CRITICAL: "bold red",
        Severity.ERROR: "red",
        Severity.WARNING: "yellow",
        Severity.INFO: "blue",
    }
    return Text(severity.value.upper(), style=colors.get(severity, "white"))


def display_result(result: ReviewResult, verbose: bool = False):
    """Display review result."""
    # Header
    console.print()
    console.print(Panel(
        f"[bold]Code Review Results[/bold]\n\n"
        f"Score: {format_score(result.score)}\n"
        f"Language: {result.language}\n"
        f"Files: {result.files_analyzed} | Lines: {result.lines_analyzed}",
        title="📊 Review Summary",
        border_style="blue",
    ))
    
    # Issues table
    if result.issues:
        table = Table(title="🔍 Issues Found", show_lines=True)
        table.add_column("File", style="cyan", no_wrap=True)
        table.add_column("Line", justify="right")
        table.add_column("Severity")
        table.add_column("Message", style="white")
        table.add_column("Rule", style="dim")
        
        for issue in result.issues[:50]:  # Limit to 50 issues
            table.add_row(
                Path(issue.file).name,
                str(issue.line),
                format_severity(issue.severity),
                issue.message[:80],
                issue.rule,
            )
        
        console.print(table)
        
        if len(result.issues) > 50:
            console.print(f"\n[yellow]... and {len(result.issues) - 50} more issues[/yellow]")
    
    # AI Analysis
    if result.ai_analysis:
        console.print()
        console.print(Panel(
            result.ai_analysis,
            title="🤖 AI Analysis",
            border_style="green",
        ))
    
    # Score breakdown
    console.print()
    console.print(Panel(
        f"[green]✅ {result.info_count} info[/green] | "
        f"[yellow]⚠️  {result.warning_count} warnings[/yellow] | "
        f"[red]❌ {result.error_count} errors[/red] | "
        f"[bold red]🔥 {result.critical_count} critical[/bold red]",
        title="📈 Issue Breakdown",
    ))


@click.group()
@click.version_option(version="0.1.0", prog_name="code-reviewer")
def cli():
    """
    🔍 AI-Powered Code Reviewer
    
    Analyze code for quality, security, and performance issues.
    """
    pass


@cli.command()
@click.argument("path", type=click.Path(exists=True))
@click.option("--ai", is_flag=True, help="Use AI for deeper analysis")
@click.option("--provider", type=click.Choice(["openai", "local"]), default="openai")
@click.option("--model", default="gpt-4", help="AI model to use")
@click.option("--fix", is_flag=True, help="Auto-fix issues")
@click.option("--dry-run", is_flag=True, help="Show fixes without applying")
@click.option("--verbose", "-v", is_flag=True, help="Verbose output")
@click.option("--output", "-o", type=click.Path(), help="Output file for results")
def review(
    path: str,
    ai: bool,
    provider: str,
    model: str,
    fix: bool,
    dry_run: bool,
    verbose: bool,
    output: Optional[str],
):
    """Review code at PATH."""
    asyncio.run(_review_async(path, ai, provider, model, fix, dry_run, verbose, output))


async def _review_async(
    path: str,
    ai: bool,
    provider_type: str,
    model: str,
    fix: bool,
    dry_run: bool,
    verbose: bool,
    output: Optional[str],
):
    """Async review implementation."""
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console,
    ) as progress:
        task = progress.add_task("Analyzing code...", total=None)
        
        # Run analysis
        analyzer = CodeAnalyzer()
        result = analyzer.analyze_path(path)
        
        progress.update(task, description="Running AI analysis...")
        
        # AI analysis if requested
        if ai:
            try:
                ai_provider = create_provider(
                    provider_type,
                    api_key="",  # Will use env var
                    model=model,
                )
                
                # Analyze each file with issues
                files_with_issues = set(i.file for i in result.issues)
                analyses = []
                
                for file_path in files_with_issues[:5]:  # Limit to 5 files
                    try:
                        content = Path(file_path).read_text(encoding="utf-8")
                        analysis = await ai_provider.analyze_code(
                            content,
                            result.language,
                            f"Focus on the {len([i for i in result.issues if i.file == file_path])} issues found.",
                        )
                        analyses.append(f"**{Path(file_path).name}:**\n{analysis}")
                    except Exception:
                        continue
                
                if analyses:
                    result.ai_analysis = "\n\n".join(analyses)
                
                if hasattr(ai_provider, 'close'):
                    await ai_provider.close()
            except Exception as e:
                console.print(f"[yellow]AI analysis failed: {e}[/yellow]")
        
        progress.update(task, description="Complete!", completed=True)
    
    # Display results
    display_result(result, verbose)
    
    # Auto-fix if requested
    if fix and result.issues:
        fixer = AutoFixer()
        
        files_to_fix = {}
        for issue in result.issues:
            if issue.file not in files_to_fix:
                files_to_fix[issue.file] = []
            files_to_fix[issue.file].append(issue)
        
        for file_path, issues in files_to_fix.items():
            try:
                content = Path(file_path).read_text(encoding="utf-8")
                fixed_content = fixer.fix(content, issues)
                
                if fixed_content != content:
                    if dry_run:
                        console.print(f"\n[cyan]Diff for {file_path}:[/cyan]")
                        diff = DiffGenerator.generate_diff(content, fixed_content, file_path)
                        console.print(Syntax(diff, "diff", theme="monokai"))
                    else:
                        Path(file_path).write_text(fixed_content, encoding="utf-8")
                        console.print(f"[green]Fixed: {file_path}[/green]")
            except Exception as e:
                console.print(f"[red]Could not fix {file_path}: {e}[/red]")
    
    # Save output if requested
    if output:
        import json
        Path(output).write_text(json.dumps(result.to_dict(), indent=2))
        console.print(f"\n[green]Results saved to {output}[/green]")
    
    # Exit code based on issues
    if result.has_critical:
        sys.exit(2)
    elif result.error_count > 0:
        sys.exit(1)
    sys.exit(0)


@cli.command()
@click.argument("code", type=str)
@click.option("--language", "-l", default="python", help="Programming language")
@click.option("--ai", is_flag=True, help="Use AI for analysis")
def analyze(code: str, language: str, ai: bool):
    """Analyze code string directly."""
    analyzer = CodeAnalyzer()
    result = analyzer.analyze_code(code, language)
    display_result(result)


@cli.command()
@click.argument("path", type=click.Path(exists=True))
@click.option("--output", "-o", type=click.Path(), help="Output file")
def stats(path: str, output: Optional[str]):
    """Show code statistics."""
    analyzer = CodeAnalyzer()
    result = analyzer.analyze_path(path)
    
    console.print()
    console.print(Panel(
        f"[bold]Code Statistics[/bold]\n\n"
        f"Files: {result.files_analyzed}\n"
        f"Lines: {result.lines_analyzed}\n"
        f"Language: {result.language}\n"
        f"Score: {result.score:.1f}/100",
        title="📊 Statistics",
    ))


def main():
    """Entry point."""
    cli()


if __name__ == "__main__":
    main()
