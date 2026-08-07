"""
Architecture patterns for software design.
"""

import re
from typing import Optional

from ..core.models import CodeIssue, Severity, IssueCategory
from ..core.rules import BaseRule


class ArchitecturePatternsRules(BaseRule):
    """Architecture pattern detection."""

    @property
    def name(self) -> str:
        return "architecture_patterns"

    @property
    def description(self) -> str:
        return "Architecture pattern detection"

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
            # Architecture styles
            (r"(?:monolith|microservice|serverless|modular|layered|clean|hexagonal|onion|ports.?adapters)", "Architecture style", "Good: choosing architecture", Severity.INFO),
            (r"(?:event.?driven|message.?driven|request.?response|pub.?sub|streaming)", "Communication style", "Good: choosing communication style", Severity.INFO),
            (r"(?:synchronous|asynchronous|batch|real.?time|near.?real.?time)", "Processing style", "Good: choosing processing style", Severity.INFO),
            (r"(?:centralized|decentralized|distributed|federated|hybrid)", "Deployment style", "Good: choosing deployment style", Severity.INFO),
            (r"(?:stateful|stateless|idempotent|fault.?tolerant|resilient)", "System property", "Good: designing system properties", Severity.INFO),
            (r"(?:scalable|elastic|auto.?scaling|horizontal|vertical)", "Scalability", "Good: designing for scalability", Severity.INFO),
            (r"(?:available|reliable|durable|consistent|partition.?tolerant)", "System property", "Good: choosing system properties", Severity.INFO),
            (r"(?:cap|acid|base|eventual.?consistency)", "Consistency model", "Good: understanding consistency", Severity.INFO),
            (r"(?:cqrs|event.?sourcing|saga|choreography|orchestration)", "Pattern style", "Good: using pattern style", Severity.INFO),
            (r"(?:domain.?driven|bounded.?context|aggregate|entity|value.?object|domain.?event)", "DDD pattern", "Good: using DDD", Severity.INFO),
            (r"(?:hexagonal|ports.?adapters|clean.?architecture|onion)", "Architecture pattern", "Good: using architecture pattern", Severity.INFO),
            (r"(?:microservice|api.?gateway|service.?mesh|sidecar|envoy)", "Microservice pattern", "Good: using microservice patterns", Severity.INFO),
            (r"(?:event.?sourcing|event.?store|projection|read.?model|write.?model)", "Event sourcing pattern", "Good: using event sourcing", Severity.INFO),
            (r"(?:cqrs|command|query|read.?model|write.?model)", "CQRS pattern", "Good: using CQRS", Severity.INFO),
            (r"(?:saga|choreography|orchestration|compensating.?transaction)", "Saga pattern", "Good: using saga pattern", Severity.INFO),
            (r"(?:domain.?driven|bounded.?context|ubiquitous.?language|aggregate|entity|value.?object)", "DDD pattern", "Good: using DDD", Severity.INFO),
            (r"(?:repository|unit.?of.?work|data.?mapper|active.?record|data.?access)", "Data access pattern", "Good: using data access pattern", Severity.INFO),
            (r"(?:factory|builder|singleton|prototype|object.?pool)", "Creational pattern", "Good: using creational pattern", Severity.INFO),
            (r"(?:adapter|bridge|composite|decorator|facade|flyweight|proxy)", "Structural pattern", "Good: using structural pattern", Severity.INFO),
            (r"(?:chain.?of.?responsibility|command|iterator|mediator|memento|observer|state|strategy|template.?method|visitor)", "Behavioral pattern", "Good: using behavioral pattern", Severity.INFO),
            (r"(?:cache|cdn|load.?balancer|reverse.?proxy|api.?gateway)", "Infrastructure pattern", "Good: using infrastructure pattern", Severity.INFO),
            (r"(?:circuit.?breaker|bulkhead|retry|timeout|fallback)", "Resilience pattern", "Good: using resilience pattern", Severity.INFO),
            (r"(?:rate.?limit|throttle|quota|backpressure)", "Flow control pattern", "Good: using flow control pattern", Severity.INFO),
            (r"(?:log|trace|metric|monitor|alert|dashboard)", "Observability pattern", "Good: using observability pattern", Severity.INFO),
            (r"(?:ci|cd|pipeline|continuous|integration|delivery|deployment)", "DevOps pattern", "Good: using DevOps pattern", Severity.INFO),
            (r"(?:test|spec|mock|stub|fixture|coverage)", "Testing pattern", "Good: using testing pattern", Severity.INFO),
            (r"(?:doc|readme|changelog|api.?doc)", "Documentation pattern", "Good: using documentation pattern", Severity.INFO),
            (r"(?:config|env|secret|vault|feature.?flag)", "Configuration pattern", "Good: using configuration pattern", Severity.INFO),
            (r"(?:auth|oauth|jwt|session|token)", "Authentication pattern", "Good: using authentication pattern", Severity.INFO),
            (r"(?:permission|role|access.?control|rbac|abac)", "Authorization pattern", "Good: using authorization pattern", Severity.INFO),
            (r"(?:backup|restore|recovery|disaster)", "Disaster recovery pattern", "Good: using disaster recovery pattern", Severity.INFO),
            (r"(?:monitoring|logging|tracing|metrics|analytics)", "Observability pattern", "Good: using observability pattern", Severity.INFO),
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
