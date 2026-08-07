"""
Comprehensive patterns database for all languages and domains.
This is the core knowledge base for code analysis.
"""

import re
from typing import Optional

from ..core.models import CodeIssue, Severity, IssueCategory
from ..core.rules import BaseRule


class ComprehensivePatterns(BaseRule):
    """Comprehensive pattern detection for all languages."""

    @property
    def name(self) -> str:
        return "comprehensive_patterns"

    @property
    def description(self) -> str:
        return "Comprehensive pattern detection"

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
            # Language detection patterns
            (r"(?:import|from|require|use|include|using|open|load)", "Import/require statement", "Good: using imports", Severity.INFO),
            (r"(?:class|struct|enum|interface|protocol|trait|type|record)", "Type definition", "Good: defining types", Severity.INFO),
            (r"(?:function|def|fn|func|method|procedure|sub|lambda|fun)", "Function definition", "Good: defining functions", Severity.INFO),
            (r"(?:if|elif|else|when|switch|match|case|select)", "Conditional statement", "Good: using conditionals", Severity.INFO),
            (r"(?:for|while|do|loop|repeat|until|each|iterate)", "Loop statement", "Good: using loops", Severity.INFO),
            (r"(?:return|yield|break|continue|throw|raise|exit)", "Control flow", "Good: using control flow", Severity.INFO),
            (r"(?:try|catch|except|finally|rescue|ensure|attempt)", "Error handling", "Good: using error handling", Severity.INFO),
            (r"(?:async|await|yield|defer|goroutine|spawn|launch)", "Async/concurrent", "Good: using async patterns", Severity.INFO),
            (r"(?:public|private|protected|internal|external|static|final|abstract|virtual|override)", "Visibility/modifier", "Good: using access control", Severity.INFO),
            (r"(?:var|let|const|final|readonly|immutable|mutable)", "Variable declaration", "Good: declaring variables", Severity.INFO),
            (r"(?:null|nil|None|undefined|NaN|void|undefined)", "Null value", "Handle null values properly", Severity.INFO),
            (r"(?:true|false|True|False|TRUE|FALSE)", "Boolean value", "Good: using boolean values", Severity.INFO),
            (r"(?:0|1|-1|2|10|100|1000)", "Numeric literal", "Good: using numeric values", Severity.INFO),
            (r"(?:\"[^\"]*\"|'[^']*')", "String literal", "Good: using string literals", Severity.INFO),
            (r"(?:\/\/|#|--|\/\*|\*\/)", "Comment syntax", "Good: using comments", Severity.INFO),
            (r"(?:\/\*\*|\/\/\/|\*\*\/)", "Documentation comment", "Good: using documentation", Severity.INFO),
            (r"(?:@\w+|#\[\w+\]|\[\w+\])", "Annotation/attribute", "Good: using annotations", Severity.INFO),
            (r"(?:=>|->|::|\.\.\.|-\>)", "Arrow/lambda syntax", "Good: using arrow functions", Severity.INFO),
            (r"(?:\?\.|\?:|!\.|!\[)", "Optional chaining", "Good: using optional chaining", Severity.INFO),
            (r"(?:\?\?|\|\||&&)", "Null coalescing/logical", "Good: using logical operators", Severity.INFO),
            (r"(?:\*\*|\^|~|<<|>>)", "Bitwise/exponent", "Good: using operators", Severity.INFO),
            (r"(?:===|!==|==|!=|<=|>=|<|>)", "Comparison operator", "Good: using comparisons", Severity.INFO),
            (r"(?:\+=|-=|\*=|/=|%=|\*\*=|\?\?=)", "Compound assignment", "Good: using compound assignment", Severity.INFO),
            (r"(?:\.\.\.|\.\.\.)", "Spread/rest operator", "Good: using spread/rest", Severity.INFO),
            (r"(?:typeof|instanceof|is|as|in|of)", "Type checking", "Good: using type checks", Severity.INFO),
            (r"(?:new|delete|void|typeof)", "Operator", "Good: using operators", Severity.INFO),
            (r"(?:\$\{|`|\${)", "Template literal", "Good: using templates", Severity.INFO),
            (r"(?:\[\]|\{\}|\(\))", "Empty collection", "Good: using collections", Severity.INFO),
            (r"(?:\.length|\.size|\.count|\.len)", "Collection size", "Good: checking size", Severity.INFO),
            (r"(?:\.push|\.pop|\.shift|\.unshift|\.append|\.insert|\.remove|\.delete)", "Collection operation", "Good: modifying collections", Severity.INFO),
            (r"(?:\.map|\.filter|\.reduce|\.forEach|\.find|\.some|\.every)", "Collection method", "Good: using collection methods", Severity.INFO),
            (r"(?:\.then|\.catch|\.finally|Promise)", "Promise pattern", "Good: using promises", Severity.INFO),
            (r"(?:try|catch|finally|throw|raise|except|rescue)", "Error handling", "Good: handling errors", Severity.INFO),
            (r"(?:console\.log|print|puts|echo|fmt\.Print|System\.out)", "Debug output", "Remove debug statements", Severity.WARNING),
            (r"(?:TODO|FIXME|HACK|XXX|NOTE|REVIEW|BUG|WORKAROUND)", "Code comment marker", "Address the issue", Severity.INFO),
            (r"(?:@deprecated|@obsolete|@legacy|@old)", "Deprecated marker", "Update deprecated code", Severity.INFO),
            (r"(?:@override|@Overload|@Override)", "Override marker", "Good: overriding methods", Severity.INFO),
            (r"(?:@static|@classmethod|@staticmethod)", "Static marker", "Good: using static methods", Severity.INFO),
            (r"(?:@property|@getter|@setter)", "Property marker", "Good: using properties", Severity.INFO),
            (r"(?:@async|@coroutine|@await)", "Async marker", "Good: using async patterns", Severity.INFO),
            (r"(?:@cache|@memoize|@lru_cache)", "Cache marker", "Good: caching results", Severity.INFO),
            (r"(?:@test|@spec|@mock|@patch|@fixture)", "Test marker", "Good: writing tests", Severity.INFO),
            (r"(?:@log|@trace|@debug|@info|@warn|@error)", "Log marker", "Good: logging appropriately", Severity.INFO),
            (r"(?:@validate|@sanitize|@escape|@encode)", "Validation marker", "Good: validating input", Severity.INFO),
            (r"(?:@authorize|@authenticate|@permission)", "Auth marker", "Good: implementing auth", Severity.INFO),
            (r"(?:@rate_limit|@throttle|@debounce|@throttle)", "Rate limiting marker", "Good: limiting requests", Severity.INFO),
            (r"(?:@retry|@backoff|@circuit_breaker)", "Resilience marker", "Good: implementing resilience", Severity.INFO),
            (r"(?:@monitor|@trace|@span|@metric)", "Observability marker", "Good: implementing observability", Severity.INFO),
            (r"(?:@optimize|@performance|@profile)", "Performance marker", "Good: optimizing performance", Severity.INFO),
            (r"(?:@security|@sanitization|@encryption)", "Security marker", "Good: implementing security", Severity.INFO),
            (r"(?:@documentation|@doc|@api)", "Documentation marker", "Good: documenting code", Severity.INFO),
            (r"(?:@version|@since|@author|@license)", "Metadata marker", "Good: adding metadata", Severity.INFO),
            (r"(?:@return|@throws|@param|@exception)", "Javadoc marker", "Good: using Javadoc", Severity.INFO),
            (r"(?:@abstractmethod|@abstract|@interface)", "Abstract marker", "Good: using abstractions", Severity.INFO),
            (r"(?:@virtual|@override|@final)", "Method modifier", "Good: using method modifiers", Severity.INFO),
            (r"(?:@readonly|@immutable|@const)", "Immutability marker", "Good: using immutability", Severity.INFO),
            (r"(?:@lazy|@eager|@deferred)", "Loading strategy", "Good: choosing loading strategy", Severity.INFO),
            (r"(?:@singleton|@prototype|@factory)", "Design pattern", "Good: using design patterns", Severity.INFO),
            (r"(?:@observer|@listener|@event)", "Event pattern", "Good: using event patterns", Severity.INFO),
            (r"(?:@strategy|@policy|@rule)", "Strategy pattern", "Good: using strategy pattern", Severity.INFO),
            (r"(?:@decorator|@wrapper|@proxy)", "Decorator pattern", "Good: using decorator pattern", Severity.INFO),
            (r"(?:@adapter|@bridge|@facade)", "Structural pattern", "Good: using structural patterns", Severity.INFO),
            (r"(?:@iterator|@generator|@stream)", "Iterator pattern", "Good: using iterator pattern", Severity.INFO),
            (r"(?:@visitor|@interpreter|@mediator)", "Behavioral pattern", "Good: using behavioral patterns", Severity.INFO),
            (r"(?:@memento|@command|@state)", "Behavioral pattern", "Good: using behavioral patterns", Severity.INFO),
            (r"(?:@chain|@pipeline|@middleware)", "Pipeline pattern", "Good: using pipeline pattern", Severity.INFO),
            (r"(?:@proxy|@remote|@local)", "Proxy pattern", "Good: using proxy pattern", Severity.INFO),
            (r"(?:@cache|@memoize|@lazy)", "Caching pattern", "Good: using caching patterns", Severity.INFO),
            (r"(?:@pool|@queue|@buffer)", "Resource management", "Good: managing resources", Severity.INFO),
            (r"(?:@retry|@circuit_breaker|@fallback)", "Resilience pattern", "Good: implementing resilience", Severity.INFO),
            (r"(?:@bulkhead|@timeout|@deadline)", "Resource management", "Good: managing resources", Severity.INFO),
            (r"(?:@monitor|@alert|@escalate)", "Monitoring pattern", "Good: monitoring systems", Severity.INFO),
            (r"(?:@audit|@log|@trace|@metric)", "Observability pattern", "Good: implementing observability", Severity.INFO),
            (r"(?:@deploy|@release|@rollback)", "Deployment pattern", "Good: managing deployments", Severity.INFO),
            (r"(?:@migrate|@backup|@restore)", "Data management", "Good: managing data", Severity.INFO),
            (r"(?:@encrypt|@decrypt|@hash|@sign)", "Crypto pattern", "Good: using cryptography", Severity.INFO),
            (r"(?:@validate|@sanitize|@escape)", "Input validation", "Good: validating input", Severity.INFO),
            (r"(?:@authorize|@authenticate|@permission)", "Auth pattern", "Good: implementing auth", Severity.INFO),
            (r"(?:@rate_limit|@throttle|@debounce)", "Rate limiting pattern", "Good: limiting requests", Severity.INFO),
            (r"(?:@cache|@invalidate|@refresh)", "Cache pattern", "Good: managing cache", Severity.INFO),
            (r"(?:@queue|@publish|@subscribe)", "Message pattern", "Good: using messages", Severity.INFO),
            (r"(?:@schedule|@cron|@timer)", "Scheduling pattern", "Good: scheduling tasks", Severity.INFO),
            (r"(?:@batch|@bulk|@stream)", "Data processing", "Good: processing data", Severity.INFO),
            (r"(?:@validate|@verify|@check)", "Validation pattern", "Good: validating data", Severity.INFO),
            (r"(?:@transform|@convert|@map)", "Data transformation", "Good: transforming data", Severity.INFO),
            (r"(?:@aggregate|@reduce|@summarize)", "Data aggregation", "Good: aggregating data", Severity.INFO),
            (r"(?:@filter|@search|@query)", "Data filtering", "Good: filtering data", Severity.INFO),
            (r"(?:@sort|@order|@rank)", "Data sorting", "Good: sorting data", Severity.INFO),
            (r"(?:@paginate|@limit|@offset)", "Data pagination", "Good: paginating data", Severity.INFO),
            (r"(?:@cache|@compress|@archive)", "Data storage", "Good: storing data", Severity.INFO),
            (r"(?:@backup|@restore|@migrate)", "Data management", "Good: managing data", Severity.INFO),
            (r"(?:@encrypt|@decrypt|@hash)", "Data security", "Good: securing data", Severity.INFO),
            (r"(?:@validate|@sanitize|@escape)", "Data validation", "Good: validating data", Severity.INFO),
            (r"(?:@transform|@convert|@normalize)", "Data transformation", "Good: transforming data", Severity.INFO),
            (r"(?:@aggregate|@reduce|@summarize)", "Data aggregation", "Good: aggregating data", Severity.INFO),
            (r"(?:@filter|@search|@query)", "Data filtering", "Good: filtering data", Severity.INFO),
            (r"(?:@sort|@order|@rank)", "Data sorting", "Good: sorting data", Severity.INFO),
            (r"(?:@paginate|@limit|@offset)", "Data pagination", "Good: paginating data", Severity.INFO),
        ]

        for line_num, line in enumerate(lines, 1):
            stripped = line.strip()
            if stripped.startswith('#') or stripped.startswith('//'):
                continue

            for pattern, message, suggestion, severity in patterns:
                if re.search(pattern, line):
                    issues.append(self._create_issue(
                        file_path=file_path,
                        line=line_num,
                        message=message,
                        suggestion=suggestion,
                        severity=severity,
                        code_snippet=stripped,
                    ))

        return issues
