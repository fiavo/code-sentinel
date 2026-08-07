"""
Design patterns for software architecture.
"""

import re
from typing import Optional

from ..core.models import CodeIssue, Severity, IssueCategory
from ..core.rules import BaseRule


class DesignPatternsRules(BaseRule):
    """Design pattern detection."""

    @property
    def name(self) -> str:
        return "design_patterns"

    @property
    def description(self) -> str:
        return "Design pattern detection"

    @property
    def category(self) -> IssueCategory:
        return IssueCategory.MAINTAINABILITY

    @property
    def severity(self) -> Severity:
        return Severity.INFO

    def check(self, file_path: str, content: str) -> list[CodeIssue]:
        issues = []
        lines = content.splitlines()

        patterns = [
            # Creational patterns
            (r"(?:factory|Factory|create|Create)", "Factory pattern", "Good: using factory pattern", Severity.INFO),
            (r"(?:builder|Builder|construct|Construct)", "Builder pattern", "Good: using builder pattern", Severity.INFO),
            (r"(?:singleton|Singleton|instance|Instance)", "Singleton pattern", "Consider using dependency injection", Severity.INFO),
            (r"(?:prototype|Prototype|clone|Clone)", "Prototype pattern", "Good: using prototype pattern", Severity.INFO),
            (r"(?:object.?pool|Pool|cache|Cache)", "Object pool pattern", "Good: using object pool", Severity.INFO),
            (r"(?:abstract.?factory|AbstractFactory)", "Abstract factory pattern", "Good: using abstract factory", Severity.INFO),
            (r"(?:lazy.?initialization|LazyInit)", "Lazy initialization", "Good: using lazy initialization", Severity.INFO),
            (r"(?:multiton|Multiton)", "Multiton pattern", "Good: using multiton pattern", Severity.INFO),

            # Structural patterns
            (r"(?:adapter|Adapter|wrapper|Wrapper)", "Adapter pattern", "Good: using adapter pattern", Severity.INFO),
            (r"(?:bridge|Bridge)", "Bridge pattern", "Good: using bridge pattern", Severity.INFO),
            (r"(?:composite|Composite)", "Composite pattern", "Good: using composite pattern", Severity.INFO),
            (r"(?:decorator|Decorator|wrapper|Wrapper)", "Decorator pattern", "Good: using decorator pattern", Severity.INFO),
            (r"(?:facade|Facade|simplified)", "Facade pattern", "Good: using facade pattern", Severity.INFO),
            (r"(?:flyweight|Flyweight|shared|Shared)", "Flyweight pattern", "Good: using flyweight pattern", Severity.INFO),
            (r"(?:proxy|Proxy|delegate|Delegate)", "Proxy pattern", "Good: using proxy pattern", Severity.INFO),
            (r"(?:private.?class.?data|PrivateClassData)", "Private class data pattern", "Good: using private class data", Severity.INFO),

            # Behavioral patterns
            (r"(?:chain.?of.?responsibility|ChainOfResponsibility)", "Chain of responsibility pattern", "Good: using chain of responsibility", Severity.INFO),
            (r"(?:command|Command|action|Action)", "Command pattern", "Good: using command pattern", Severity.INFO),
            (r"(?:iterator|Iterator|traverse|Traverse)", "Iterator pattern", "Good: using iterator pattern", Severity.INFO),
            (r"(?:mediator|Mediator|coordinator|Coordinator)", "Mediator pattern", "Good: using mediator pattern", Severity.INFO),
            (r"(?:memento|Memento|snapshot|Snapshot)", "Memento pattern", "Good: using memento pattern", Severity.INFO),
            (r"(?:observer|Observer|listener|Listener|event|Event)", "Observer pattern", "Good: using observer pattern", Severity.INFO),
            (r"(?:state|State|transition|Transition)", "State pattern", "Good: using state pattern", Severity.INFO),
            (r"(?:strategy|Strategy|policy|Policy)", "Strategy pattern", "Good: using strategy pattern", Severity.INFO),
            (r"(?:template.?method|TemplateMethod)", "Template method pattern", "Good: using template method", Severity.INFO),
            (r"(?:visitor|Visitor)", "Visitor pattern", "Good: using visitor pattern", Severity.INFO),
            (r"(?:interpreter|Interpreter|parser|Parser)", "Interpreter pattern", "Good: using interpreter pattern", Severity.INFO),
            (r"(?:mediator|Mediator|controller|Controller)", "Mediator pattern", "Good: using mediator pattern", Severity.INFO),
            (r"(?:null.?object|NullObject)", "Null object pattern", "Good: using null object pattern", Severity.INFO),
            (r"(?:service.?locator|ServiceLocator)", "Service locator pattern", "Consider using dependency injection", Severity.INFO),
            (r"(?:specification|Specification)", "Specification pattern", "Good: using specification pattern", Severity.INFO),
            (r"(?:repository|Repository)", "Repository pattern", "Good: using repository pattern", Severity.INFO),
            (r"(?:unit.?of.?work|UnitOfWork)", "Unit of work pattern", "Good: using unit of work", Severity.INFO),
            (r"(?:data.?mapper|DataMapper)", "Data mapper pattern", "Good: using data mapper", Severity.INFO),
            (r"(?:active.?record|ActiveRecord)", "Active record pattern", "Good: using active record", Severity.INFO),
            (r"(?:value.?object|ValueObject)", "Value object pattern", "Good: using value object", Severity.INFO),
            (r"(?:entity|Entity|domain)", "Entity pattern", "Good: using entity pattern", Severity.INFO),
            (r"(?:aggregate|Aggregate|root)", "Aggregate pattern", "Good: using aggregate pattern", Severity.INFO),
            (r"(?:domain.?event|DomainEvent)", "Domain event pattern", "Good: using domain events", Severity.INFO),
            (r"(?:saga|Saga|process.?manager)", "Saga pattern", "Good: using saga pattern", Severity.INFO),
            (r"(?:event.?sourcing|EventSourcing)", "Event sourcing pattern", "Good: using event sourcing", Severity.INFO),
            (r"(?:cqrs|CQRS)", "CQRS pattern", "Good: using CQRS", Severity.INFO),
            (r"(?:domain.?driven|DDD)", "Domain-driven design", "Good: using DDD", Severity.INFO),
            (r"(?:hexagonal|ports.?adapters|clean.?architecture)", "Architecture pattern", "Good: using clean architecture", Severity.INFO),
            (r"(?:microservice|monolith|serverless)", "Architecture style", "Good: choosing architecture", Severity.INFO),
            (r"(?:event.?driven|message.?driven)", "Architecture style", "Good: using event-driven architecture", Severity.INFO),
            (r"(?:actor|actor.?model|message.?passing)", "Actor model", "Good: using actor model", Severity.INFO),
            (r"(?:pipeline|middleware|chain)", "Pipeline pattern", "Good: using pipeline pattern", Severity.INFO),
            (r"(?:plugin|extension|addon)", "Plugin pattern", "Good: using plugin pattern", Severity.INFO),
            (r"(?:hook|callback|delegate)", "Hook pattern", "Good: using hook pattern", Severity.INFO),
            (r"(?:strategy|policy|rule)", "Strategy pattern", "Good: using strategy pattern", Severity.INFO),
            (r"(?:template|skeleton|boilerplate)", "Template pattern", "Good: using template pattern", Severity.INFO),
            (r"(?:visitor|traverser|scanner)", "Visitor pattern", "Good: using visitor pattern", Severity.INFO),
            (r"(?:interpreter|evaluator|parser)", "Interpreter pattern", "Good: using interpreter pattern", Severity.INFO),
            (r"(?:iterator|generator|stream)", "Iterator pattern", "Good: using iterator pattern", Severity.INFO),
            (r"(?:observer|listener|subscriber)", "Observer pattern", "Good: using observer pattern", Severity.INFO),
            (r"(?:mediator|coordinator|controller)", "Mediator pattern", "Good: using mediator pattern", Severity.INFO),
            (r"(?:memento|snapshot|checkpoint)", "Memento pattern", "Good: using memento pattern", Severity.INFO),
            (r"(?:command|action|task)", "Command pattern", "Good: using command pattern", Severity.INFO),
            (r"(?:state|status|phase)", "State pattern", "Good: using state pattern", Severity.INFO),
            (r"(?:chain|pipeline|middleware)", "Chain pattern", "Good: using chain pattern", Severity.INFO),
            (r"(?:null.?object|default.?object)", "Null object pattern", "Good: using null object pattern", Severity.INFO),
            (r"(?:service.?locator|registry|container)", "Service locator pattern", "Consider using dependency injection", Severity.INFO),
            (r"(?:specification|criteria|predicate)", "Specification pattern", "Good: using specification pattern", Severity.INFO),
            (r"(?:repository|dao|mapper)", "Repository pattern", "Good: using repository pattern", Severity.INFO),
            (r"(?:unit.?of.?work|transaction)", "Unit of work pattern", "Good: using unit of work", Severity.INFO),
            (r"(?:data.?mapper|data.?access)", "Data mapper pattern", "Good: using data mapper", Severity.INFO),
            (r"(?:active.?record|orm)", "Active record pattern", "Good: using active record", Severity.INFO),
            (r"(?:value.?object|immutable)", "Value object pattern", "Good: using value object", Severity.INFO),
            (r"(?:entity|domain.?model)", "Entity pattern", "Good: using entity pattern", Severity.INFO),
            (r"(?:aggregate|root|boundary)", "Aggregate pattern", "Good: using aggregate pattern", Severity.INFO),
            (r"(?:domain.?event|event)", "Domain event pattern", "Good: using domain events", Severity.INFO),
            (r"(?:saga|process.?manager|workflow)", "Saga pattern", "Good: using saga pattern", Severity.INFO),
            (r"(?:event.?sourcing|event.?store)", "Event sourcing pattern", "Good: using event sourcing", Severity.INFO),
            (r"(?:cqrs|command.?query)", "CQRS pattern", "Good: using CQRS", Severity.INFO),
        ]

        for line_num, line in enumerate(lines, 1):
            stripped = line.strip()
            if stripped.startswith('#') or stripped.startswith('//'):
                continue

            for pattern, message, suggestion, severity in patterns:
                if re.search(pattern, line, re.IGNORECASE):
                    issues.append(self._create_issue(
                        file_path=file_path,
                        line=line_num,
                        message=message,
                        suggestion=suggestion,
                        severity=severity,
                        code_snippet=stripped,
                    ))

        return issues
