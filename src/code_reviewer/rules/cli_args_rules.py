"""
CLI argument parsing and command-line patterns.
"""
import re
from ..core.models import CodeIssue, Severity, IssueCategory
from ..core.rules import BaseRule


class CLIArgsRules(BaseRule):
    @property
    def name(self) -> str:
        return "cli_args"
    @property
    def description(self) -> str:
        return "CLI argument parsing and command-line patterns"
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
            # Python CLI
            (r"argparse|sys\.argv|click|typer|fire|docopt|optparse|getopt|cleo|cliprompt|questionary|inquirer|pick|PyInquirer|blessed|curses|prompt_toolkit|rich|rich\.click|rich\.prompt|rich\.console", "Python CLI tools", "Good: Python CLI tools", Severity.INFO),
            (r"ArgumentParser|add_argument|parse_args|subparsers|add_parser|add_mutually_exclusive_group|add_argument_group|set_defaults|parse_known_args", "argparse usage", "Good: argparse", Severity.INFO),
            (r"@click\.command|@click\.option|@click\.argument|@click\.group|@click\.pass_context|@click\.pass_obj|@click\.confirm|@click\.prompt|@click\.choice|@click\.file|@click\.path|@click\.glob|@click\.DateTime|@click\.IntRange|@click\.FloatRange|@click\.Choice|click\.echo|click\.style|click\.secho|click\.format_filename|click\.get_text_stream|click\.get_binary_stream|click\.get_current_context", "Click usage", "Good: Click", Severity.INFO),
            (r"@typer\.Typer|typer\.Typer|typer\.Option|typer\.Argument|typer\.Help|typer\.Exit|typer\.Prompt|typer\.Confirm|typer\.Choice|typer\.Path|typer\.FileText|typer\.FileBinaryRead|typer\.FileBinaryWrite|typer\.FileTextWrite|typer\.FileTextRead|typer\.URL|typer\.Email", "Typer usage", "Good: Typer", Severity.INFO),
            (r"import\s+fire|fire\.Fire\(|fire\.Fire", "Fire usage", "Good: Fire", Severity.INFO),
            # JavaScript CLI
            (r"yargs|commander|meow|caporal|oclif|arg|minimist|meow|clipanion|gluegun|vorpal|inquirer|prompts|enquirer|ora|chalk|boxen|ora|listr|ink|blessed|terminal-kit|vorpal", "JS CLI tools", "Good: JS CLI tools", Severity.INFO),
            (r"process\.argv|process\.env|process\.stdin|process\.stdout|process\.stderr", "Node.js process", "Good: Node.js process", Severity.INFO),
            # Go CLI
            (r"flag\.String|flag\.Int|flag\.Bool|flag\.Float64|flag\.Duration|flag\.Var|flag\.Parse|flag\.Args|flag\.NArg|flag\.NFlag|flag\.Arg|flag\.Visit|flag\.VisitAll", "Go flag package", "Good: Go flag", Severity.INFO),
            (r"cobra|spf13/cobra|pflag|spf13/pflag|kingpin|go-flags|docopt-go|urfave/cli|urfave/cli/v2|mitchellh/cli|jessevdk/go-flags|akamensky/argparse|jessevdk/go-flags|taiki42/pflag|alexflint/go-arg|alecthomas/kingpin", "Go CLI frameworks", "Good: Go CLI frameworks", Severity.INFO),
            # Rust CLI
            (r"clap|clap::Parser|clap::Subcommand|clap::Args|structopt|structopt::StructOpt|argh|argh::FromArgs|bpaf|bpaf::Parser|lexopt|lexopt::Parser", "Rust CLI frameworks", "Good: Rust CLI frameworks", Severity.INFO),
            # Java CLI
            (r"commons-cli|picocli|picocli\.|args4j|JCommander|jcommander|picocli\.CommandLine|picocli\.CommandLine\.Command|picocli\.CommandLine\.Option|picocli\.CommandLine\.Parameters|picocli\.CommandLine\.Mixin|picocli\.CommandLine\.Spec|picocli\.CommandLine\.IFactory|picocli\.CommandLine\.ExecutionException|picocli\.CommandLine\.ParameterException|picocli\.CommandLine\.ParseResult", "Java CLI tools", "Good: Java CLI tools", Severity.INFO),
            # PHP CLI
            (r"symfony/console|Console|InputInterface|OutputInterface|Command|Application|ArgvInput|ArrayInput|StringInput|StreamInput|BufferedOutput|ConsoleOutput|SectionOutput|StreamOutput|NullOutput|FormatterStyle|OutputFormatter|OutputFormatterStyle|QuestionHelper|ChoiceQuestion|ConfirmationQuestion|Question", "PHP CLI tools", "Good: PHP CLI tools", Severity.INFO),
            # CLI patterns
            (r"\-\-help|\-h|\-\-version|\-v|\-\-verbose|\-q|\-\-quiet|\-\-debug|\-\-dry-run|\-\-force|\-\-no-color|\-\-color|\-\-output|\-o|\-\-input|\-i|\-\-config|\-c|\-\-file|\-f|\-\-dir|\-d|\-\-recursive|\-r|\-\-all|\-a|\-\-verbose|\-V|\-\-quiet|\-q|\-\-silent|\-\-interactive|\-i|\-\-batch|\-\-no-prompt|\-\-yes|\-y|\-\-no|\-n", "CLI flags", "Good: CLI flags", Severity.INFO),
            (r"\-\-help\b|\-h\b|\-\-version\b|\-V\b|\-\-verbose\b|\-v\b|\-\-quiet\b|\-q\b|\-\-debug\b|\-\-trace\b|\-\-dry-run\b|\-\-force\b|\-\-yes\b|\-y\b|\-\-no\b|\-n\b|\-\-color\b|\-\-no-color\b|\-\-interactive\b|\-i\b", "CLI option", "Good: CLI option", Severity.INFO),
            (r"subcommand|SubCommand|sub_command|subparser|SubParser|sub_parser|command.*add_parser|command.*addCommand|command.*command\(|command.*cli\(|command.*app\(", "Subcommand pattern", "Good: subcommands", Severity.INFO),
            (r"help=|metavar=|choices=|nargs=|default=|required=|dest=|action=|const=|type=|callback=|envvar=|env_var=|hidden=|hidden=True|show_default=|show_envvar=|prompt=|confirmation_prompt=|is_eager=|expose_value=|autocompletion=|rich_help_panel=", "CLI parameter options", "Good: CLI parameters", Severity.INFO),
            (r"progress.?bar|ProgressBar|progress_bar|spinner|Spinner|loading|Loading|tqdm|click\.progressbar|typer\.progress|rich\.progress|rich\.status|rich\.live|rich\.spinner|rich\.column|rich\.table|rich\.panel|rich\.text|rich\.tree|rich\.layout|rich\.console|rich\.prompt|rich\.confirm|rich\.select|rich\.multiselect|rich\.text|rich\.markdown|rich\.syntax|rich\.traceback", "CLI progress", "Good: progress indicators", Severity.INFO),
            (r"color|Color|style|Style|theme|Theme|format|Format|highlight|Highlight|ansi|ANSI|escape|Escape|bold|Bold|italic|Italic|underline|Underline|strikethrough|Strikethrough|dim|Dim|blink|Blink|reverse|Reverse|hidden|Hidden|reset|Reset", "CLI formatting", "Good: CLI formatting", Severity.INFO),
            (r"prompt|Prompt|confirm|Confirm|input|Input|select|Select|multi_select|MultiSelect|checkbox|Checkbox|radio|Radio|autocomplete|Autocomplete|password|Password|secret|Secret|hidden|Hidden", "CLI interaction", "Good: CLI interaction", Severity.INFO),
            (r"shell|Shell|bash|Bash|zsh|Zsh|fish|Fish|powershell|PowerShell|cmd|CMD|batch|Batch|pwsh|PWSH|nushell|Nushell|xonsh|Xonsh", "Shell", "Good: shells", Severity.INFO),
            (r"completion|Completion|COMPLETION|autocomplete|Autocomplete|AUTOCOMPLETE|tab.?complete|TabComplete|tab_complete|zsh.?completion|bash.?completion|fish.?completion|powershell.?completion", "CLI completion", "Good: CLI completions", Severity.INFO),
            (r"exit\s+0|exit\s+1|sys\.exit|process\.exit|os\._exit|abort\(\)|panic!\(|unwrap\(\)|panic!\(|eprintln!|panic!|os\.exit|sys\.exit\(|process\.exit\(|std::process::exit", "CLI exit", "Good: CLI exit codes", Severity.INFO),
            (r"stdin|stdout|stderr|STDIN|STDOUT|STDERR|sys\.stdin|sys\.stdout|sys\.stderr|process\.stdin|process\.stdout|process\.stderr|std::io::stdin|std::io::stdout|std::io::stderr|io\.Stdin|io\.Stdout|io\.Stderr", "CLI streams", "Good: CLI streams", Severity.INFO),
            (r"pipe|Pipe|PIPE|redirection|Redirection|REDIRECTION|redirect|Redirect|REDIRECT|here.?doc|HereDoc|here_doc|heredoc|HEREDOC|process.?substitution|ProcessSubstitution", "CLI piping", "Good: CLI piping", Severity.INFO),
            (r"man\s+page|manpage|ManPage|man_page|help\.txt|HELP\.txt|USAGE\.txt|usage\.txt|README\.txt|readme\.txt|INSTALL\.txt|install\.txt|CONTRIBUTING\.txt|contributing\.txt|CHANGELOG\.txt|changelog\.txt|LICENSE\.txt|license\.txt", "CLI docs", "Good: CLI documentation", Severity.INFO),
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
