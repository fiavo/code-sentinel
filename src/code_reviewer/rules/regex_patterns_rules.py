"""
Regex and string processing patterns.
"""
import re
from ..core.models import CodeIssue, Severity, IssueCategory
from ..core.rules import BaseRule


class RegexPatternsRules(BaseRule):
    @property
    def name(self) -> str:
        return "regex_patterns"
    @property
    def description(self) -> str:
        return "Regex and string processing patterns"
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
            # Regex features
            (r"re\.compile\(|re\.match\(|re\.search\(|re\.findall\(|re\.sub\(|re\.split\(|re\.finditer\(|re\.fullmatch\(|re\.escape\(|re\.purge\(", "Python regex", "Good: Python regex", Severity.INFO),
            (r"new RegExp\(|RegExp\(|\.match\(|\.replace\(|\.search\(|\.split\(|\.test\(|\.exec\(|\.matchAll\(", "JavaScript regex", "Good: JS regex", Severity.INFO),
            (r"Regex::new\(|Regex::is_match\(|captures\(|find\(|find_iter\(|replace\(|replacen\(|split\(|splitn\(|is_match\(|as_str\(\)|RegexSet::new\(|Captures::", "Rust regex", "Good: Rust regex", Severity.INFO),
            (r"regexp.MustCompile\(|regexp\.Compile\(|FindString\(|FindAllString\(|ReplaceAllString\(|Split\(|MatchString\(|SubexpIndex\(|SubexpNames\(|Longest\(|NamedGroups\(|ExpandString\(", "Go regex", "Good: Go regex", Severity.INFO),
            (r"Pattern\.compile\(|Pattern\.matches\(|Pattern\.split\(|Matcher\.find\(|Matcher\.matches\(|Matcher\.group\(|Matcher\.replaceAll\(|Matcher\.replaceFirst\(", "Java regex", "Good: Java regex", Severity.INFO),
            (r"preg_match\(|preg_replace\(|preg_split\(|preg_match_all\(|preg_quote\(|preg_last_error\(", "PHP regex", "Good: PHP regex", Severity.INFO),
            # Common regex patterns
            (r"\\d|\\w|\\s|\\b|\\D|\\W|\\S|\\B", "Character class", "Good: character class", Severity.INFO),
            (r"\[.*\]|\(.*\)|\{.*\}", "Regex grouping", "Good: regex grouping", Severity.INFO),
            (r"\+|\*|\?|\^|\$|\.|\||\\", "Regex metacharacter", "Good: regex metacharacter", Severity.INFO),
            (r"(?:\.\*|\.\+)", "Greedy quantifier", "Consider non-greedy quantifier", Severity.INFO),
            (r"(?:\.\*\?|\.\+\?)", "Non-greedy quantifier", "Good: non-greedy", Severity.INFO),
            (r"(?:lookahead|lookbehind|(?=|\?!|(?<=|\(?<!)", "Lookaround", "Good: lookaround", Severity.INFO),
            (r"(?:backreference|\\[1-9]|\\k<\w+>)", "Backreference", "Good: backreference", Severity.INFO),
            (r"(?:named group|\(\?P<|\(\?<\w+>)", "Named group", "Good: named group", Severity.INFO),
            (r"(?:inline flags|\(\?[a-z]+\))", "Inline flags", "Good: inline flags", Severity.INFO),
            (r"(?:non-capturing group|(?:))", "Non-capturing group", "Good: non-capturing group", Severity.INFO),
            (r"(?:atomic group|(?>|\\A|\\z|\\Z)", "Atomic group", "Good: atomic group", Severity.INFO),
            (r"(?:conditional|\\(\\(|\\)|\\|)", "Conditional", "Good: conditional regex", Severity.INFO),
            # Common regex usage
            (r"email|email.?address|Email|EMAIL", "Email pattern", "Good: email pattern", Severity.INFO),
            (r"url|URL|uri|URI|http|https|ftp|ftps", "URL pattern", "Good: URL pattern", Severity.INFO),
            (r"ip|IP|ipv4|IPv4|ipv6|IPv6", "IP pattern", "Good: IP pattern", Severity.INFO),
            (r"phone|telephone|mobile|fax|Phone|PHONE", "Phone pattern", "Good: phone pattern", Severity.INFO),
            (r"date|time|datetime|timestamp|Date|Time|DateTime|Timestamp", "Date/time pattern", "Good: date/time pattern", Severity.INFO),
            (r"zip|postal|ZIP|Postal|ZIPCODE|PostalCode", "ZIP code pattern", "Good: ZIP code pattern", Severity.INFO),
            (r"ssn|social.?security|SSN|SocialSecurity", "SSN pattern", "Good: SSN pattern", Severity.INFO),
            (r"credit.?card|CreditCard|credit.?number|CreditNumber|card.?number|CardNumber", "Credit card pattern", "Good: credit card pattern", Severity.INFO),
            (r"password|Password|PASSWORD|passwd|passwd|pwd|Pwd|PWD", "Password pattern", "Good: password pattern", Severity.INFO),
            (r"username|UserName|user.?name|User.?Name|login|Login|LOGIN", "Username pattern", "Good: username pattern", Severity.INFO),
            (r"hex|HEX|hexadecimal|Hexadecimal|HEXADECIMAL|rgb|RGB|rgba|RGBA|color|Color|COLOR", "Color pattern", "Good: color pattern", Severity.INFO),
            (r"html|HTML|xml|XML|json|JSON|yaml|YAML|csv|CSV|markdown|Markdown|MARKDOWN", "Data format pattern", "Good: data format pattern", Severity.INFO),
            (r"sql|SQL|SELECT|INSERT|UPDATE|DELETE|CREATE|DROP|ALTER|TABLE|INDEX|VIEW|FUNCTION|PROCEDURE|TRIGGER|EVENT|DATABASE|SCHEMA|GRANT|REVOKE|COMMIT|ROLLBACK|SAVEPOINT|BEGIN|END|IF|ELSE|THEN|LOOP|WHILE|FOR|REPEAT|CASE|WHEN|LIKE|IN|EXISTS|NOT|AND|OR|BETWEEN|IS|NULL|TRUE|FALSE", "SQL pattern", "Good: SQL pattern", Severity.INFO),
            (r"regex|regular.?expression|regexp|regexp|pattern|Pattern|PATTERN", "Regex reference", "Good: regex reference", Severity.INFO),
            # String processing
            (r"split|Split|join|Join|trim|Trim|slice|Slice|substring|Substring|replace|Replace|reverse|Reverse|capitalize|Capitalize|title|Title|upper|Upper|lower|Lower|lstrip|rstrip|strip|Strip|find|Find|indexOf|IndexOf|contains|Contains|startsWith|StartsWith|endsWith|EndsWith|pad|Pad|repeat|Repeat|format|Format|sprintf|printf|concat|Concat", "String operation", "Good: string operations", Severity.INFO),
            (r"encode|Encode|decode|Decode|escape|Escape|unescape|Unescape|quote|Quote|unquote|Unquote|percent.?encode|PercentEncode|url.?encode|URLEncode|html.?encode|HTMLEncode|base64|Base64|urldecode|URLDecode|urldecode|HTMLDecode|base64_decode", "Encoding/decoding", "Good: encoding/decoding", Severity.INFO),
            (r"template|Template|interpolation|Interpolation|format!|format|f\"|f'|sprintf|printf|gsub|gsub|replace|Replace", "String formatting", "Good: string formatting", Severity.INFO),
            (r"regex|Regex|RE|regexp|Regexp|regexp|pattern|Pattern|matcher|Matcher|match|Match", "Regex usage", "Good: regex usage", Severity.INFO),
            (r"string|String|str|Str|char|Char|character|Character|charAt|charAt|codePointAt|codePointAt|codePointBefore|codePointBefore|codePointCount|codePointCount", "String/char type", "Good: string/char types", Severity.INFO),
        ]
        for line_num, line in enumerate(lines, 1):
            stripped = line.strip()
            if stripped.startswith('#') or stripped.startswith('//') or stripped.startswith('/*'):
                continue
            for pattern, message, severity in patterns:
                if re.search(pattern, line):
                    issues.append(self._create_issue(
                        file_path=file_path, line=line_num, message=message,
                        suggestion=message, severity=severity, code_snippet=stripped,
                    ))
        return issues
