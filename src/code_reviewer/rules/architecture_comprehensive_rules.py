"""
Comprehensive architecture patterns for software design.
"""
import re
from ..core.models import CodeIssue, Severity, IssueCategory
from ..core.rules import BaseRule


class ArchitectureComprehensiveRules(BaseRule):
    @property
    def name(self) -> str:
        return "architecture_comprehensive"
    @property
    def description(self) -> str:
        return "Comprehensive architecture patterns"
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
            (r"monolith|microservice|serverless|modular|layered|clean|hexagonal|onion|ports.?adapters", "Architecture style", "Good: choosing architecture", Severity.INFO),
            (r"event.?driven|message.?driven|request.?response|pub.?sub|streaming", "Communication style", "Good: choosing communication style", Severity.INFO),
            (r"synchronous|asynchronous|batch|real.?time|near.?real.?time", "Processing style", "Good: choosing processing style", Severity.INFO),
            (r"centralized|decentralized|distributed|federated|hybrid", "Deployment style", "Good: choosing deployment style", Severity.INFO),
            (r"stateful|stateless|idempotent|fault.?tolerant|resilient", "System property", "Good: designing system properties", Severity.INFO),
            (r"scalable|elastic|auto.?scaling|horizontal|vertical", "Scalability", "Good: designing for scalability", Severity.INFO),
            (r"available|reliable|durable|consistent|partition.?tolerant", "System property", "Good: choosing system properties", Severity.INFO),
            (r"cap|acid|base|eventual.?consistency", "Consistency model", "Good: understanding consistency", Severity.INFO),
            # DDD
            (r"cqrs|event.?sourcing|saga|choreography|orchestration", "Pattern style", "Good: using pattern style", Severity.INFO),
            (r"domain.?driven|bounded.?context|aggregate|entity|value.?object|domain.?event", "DDD pattern", "Good: using DDD", Severity.INFO),
            (r"hexagonal|ports.?adapters|clean.?architecture|onion", "Architecture pattern", "Good: using architecture pattern", Severity.INFO),
            (r"microservice|api.?gateway|service.?mesh|sidecar|envoy", "Microservice pattern", "Good: using microservice patterns", Severity.INFO),
            (r"event.?sourcing|event.?store|projection|read.?model|write.?model", "Event sourcing pattern", "Good: using event sourcing", Severity.INFO),
            (r"cqrs|command|query|read.?model|write.?model", "CQRS pattern", "Good: using CQRS", Severity.INFO),
            (r"saga|choreography|orchestration|compensating.?transaction", "Saga pattern", "Good: using saga pattern", Severity.INFO),
            (r"domain.?driven|bounded.?context|ubiquitous.?language|aggregate|entity|value.?object", "DDD pattern", "Good: using DDD", Severity.INFO),
            (r"repository|unit.?of.?work|data.?mapper|active.?record|data.?access", "Data access pattern", "Good: using data access pattern", Severity.INFO),
            (r"factory|builder|singleton|prototype|object.?pool", "Creational pattern", "Good: using creational pattern", Severity.INFO),
            (r"adapter|bridge|composite|decorator|facade|flyweight|proxy", "Structural pattern", "Good: using structural pattern", Severity.INFO),
            (r"chain.?of.?responsibility|command|iterator|mediator|memento|observer|state|strategy|template.?method|visitor", "Behavioral pattern", "Good: using behavioral pattern", Severity.INFO),
            (r"cache|cdn|load.?balancer|reverse.?proxy|api.?gateway", "Infrastructure pattern", "Good: using infrastructure pattern", Severity.INFO),
            (r"circuit.?breaker|bulkhead|retry|timeout|fallback", "Resilience pattern", "Good: using resilience pattern", Severity.INFO),
            (r"rate.?limit|throttle|quota|backpressure", "Flow control pattern", "Good: using flow control pattern", Severity.INFO),
            (r"log|trace|metric|monitor|alert|dashboard", "Observability pattern", "Good: using observability pattern", Severity.INFO),
            (r"ci|cd|pipeline|continuous|integration|delivery|deployment", "DevOps pattern", "Good: using DevOps pattern", Severity.INFO),
            (r"test|spec|mock|stub|fixture|coverage", "Testing pattern", "Good: using testing pattern", Severity.INFO),
            (r"doc|readme|changelog|api.?doc", "Documentation pattern", "Good: using documentation pattern", Severity.INFO),
            (r"config|env|secret|vault|feature.?flag", "Configuration pattern", "Good: using configuration pattern", Severity.INFO),
            (r"auth|oauth|jwt|session|token", "Authentication pattern", "Good: using authentication pattern", Severity.INFO),
            (r"permission|role|access.?control|rbac|abac", "Authorization pattern", "Good: using authorization pattern", Severity.INFO),
            (r"backup|restore|recovery|disaster", "Disaster recovery pattern", "Good: using disaster recovery pattern", Severity.INFO),
            (r"monitoring|logging|tracing|metrics|analytics", "Observability pattern", "Good: using observability pattern", Severity.INFO),
            # SOLID principles
            (r"single.?responsibility|SRP", "Single Responsibility Principle", "Good: following SRP", Severity.INFO),
            (r"open.?closed|OCP", "Open-Closed Principle", "Good: following OCP", Severity.INFO),
            (r"liskov.?substitution|LSP", "Liskov Substitution Principle", "Good: following LSP", Severity.INFO),
            (r"interface.?segregation|ISP", "Interface Segregation Principle", "Good: following ISP", Severity.INFO),
            (r"dependency.?inversion|DIP", "Dependency Inversion Principle", "Good: following DIP", Severity.INFO),
            # Design principles
            (r"DRY|Don't Repeat Yourself", "DRY principle", "Good: following DRY", Severity.INFO),
            (r"KISS|Keep It Simple", "KISS principle", "Good: following KISS", Severity.INFO),
            (r"YAGNI|You Aren't Gonna Need It", "YAGNI principle", "Good: following YAGNI", Severity.INFO),
            (r"Separation of Concerns|SoC", "Separation of Concerns", "Good: separating concerns", Severity.INFO),
            (r"Composition over Inheritance", "Composition over Inheritance", "Good: composition over inheritance", Severity.INFO),
            # Architectural patterns
            (r"MVC|Model.?View.?Controller", "MVC pattern", "Good: using MVC", Severity.INFO),
            (r"MVP|Model.?View.?Presenter", "MVP pattern", "Good: using MVP", Severity.INFO),
            (r"MVVM|Model.?View.?ViewModel", "MVVM pattern", "Good: using MVVM", Severity.INFO),
            (r"MVI|Model.?View.?Intent", "MVI pattern", "Good: using MVI", Severity.INFO),
            (r"flux|Flux", "Flux pattern", "Good: using Flux", Severity.INFO),
            (r"unidirectional.?data.?flow|UDF", "Unidirectional data flow", "Good: using UDF", Severity.INFO),
            # Microservice patterns
            (r"service.?discovery|Service.?Registry", "Service discovery", "Good: service discovery", Severity.INFO),
            (r"api.?gateway|API.?Gateway", "API gateway", "Good: API gateway pattern", Severity.INFO),
            (r"sidecar|Sidecar", "Sidecar pattern", "Good: sidecar pattern", Severity.INFO),
            (r"ambassador|Ambassador", "Ambassador pattern", "Good: ambassador pattern", Severity.INFO),
            (r"strangler|Strangler.?Fig", "Strangler fig pattern", "Good: strangler fig pattern", Severity.INFO),
            (r"blue.?green|Blue.?Green", "Blue-green deployment", "Good: blue-green deployment", Severity.INFO),
            (r"canary|Canary", "Canary deployment", "Good: canary deployment", Severity.INFO),
            (r"rolling|Rolling", "Rolling deployment", "Good: rolling deployment", Severity.INFO),
            (r"feature.?flag|Feature.?Toggle", "Feature flags", "Good: feature flags", Severity.INFO),
            (r"sidecar|Sidecar", "Sidecar pattern", "Good: sidecar pattern", Severity.INFO),
            (r"ambassador|Ambassador", "Ambassador pattern", "Good: ambassador pattern", Severity.INFO),
            # Data patterns
            (r"event.?sourcing|Event.?Sourcing", "Event sourcing", "Good: event sourcing", Severity.INFO),
            (r"CQRS|Command.?Query.?Responsibility.?Segregation", "CQRS", "Good: CQRS", Severity.INFO),
            (r"saga|Saga", "Saga pattern", "Good: saga pattern", Severity.INFO),
            (r"choreography|Choreography", "Choreography", "Good: choreography", Severity.INFO),
            (r"orchestration|Orchestration", "Orchestration", "Good: orchestration", Severity.INFO),
            (r"outbox|Outbox", "Transactional outbox", "Good: transactional outbox", Severity.INFO),
            (r"saga|Saga", "Saga pattern", "Good: saga pattern", Severity.INFO),
            (r"event.?carry.?state.?flag|Event.?Carry.?State.?Flag", "Event carry state flag", "Good: event carry state flag", Severity.INFO),
            # Integration patterns
            (r"message.?router|Message.?Router", "Message router", "Good: message router", Severity.INFO),
            (r"content.?enricher|Content.?Enricher", "Content enricher", "Good: content enricher", Severity.INFO),
            (r"content.?filter|Content.?Filter", "Content filter", "Good: content filter", Severity.INFO),
            (r"message.?filter|Message.?Filter", "Message filter", "Good: message filter", Severity.INFO),
            (r"splitter|Splitter", "Splitter pattern", "Good: splitter pattern", Severity.INFO),
            (r"aggregator|Aggregator", "Aggregator pattern", "Good: aggregator pattern", Severity.INFO),
            (r"resequencer|Resequencer", "Resequencer pattern", "Good: resequencer pattern", Severity.INFO),
            (r"correlation.?id|Correlation.?ID", "Correlation ID", "Good: correlation ID", Severity.INFO),
            (r"message.?id|Message.?ID", "Message ID", "Good: message ID", Severity.INFO),
            # Resilience patterns
            (r"circuit.?breaker|Circuit.?Breaker", "Circuit breaker", "Good: circuit breaker", Severity.INFO),
            (r"bulkhead|Bulkhead", "Bulkhead pattern", "Good: bulkhead pattern", Severity.INFO),
            (r"retry|Retry", "Retry pattern", "Good: retry pattern", Severity.INFO),
            (r"fallback|Fallback", "Fallback pattern", "Good: fallback pattern", Severity.INFO),
            (r"timeout|Timeout", "Timeout pattern", "Good: timeout pattern", Severity.INFO),
            (r"rate.?limiter|Rate.?Limiter", "Rate limiter", "Good: rate limiter", Severity.INFO),
            (r"throttler|Throttler", "Throttler pattern", "Good: throttler pattern", Severity.INFO),
            (r"load.?shedder|Load.?Shedder", "Load shedder", "Good: load shedder", Severity.INFO),
            # Security patterns
            (r"defense.?in.?depth|Defense.?in.?Depth", "Defense in depth", "Good: defense in depth", Severity.INFO),
            (r"least.?privilege|Least.?Privilege", "Least privilege", "Good: least privilege", Severity.INFO),
            (r"zero.?trust|Zero.?Trust", "Zero trust", "Good: zero trust", Severity.INFO),
            (r"segmentation|Segmentation", "Network segmentation", "Good: network segmentation", Severity.INFO),
            (r"encryption.?at.?rest|Encryption.?at.?Rest", "Encryption at rest", "Good: encryption at rest", Severity.INFO),
            (r"encryption.?in.?transit|Encryption.?in.?Transit", "Encryption in transit", "Good: encryption in transit", Severity.INFO),
            # Monitoring patterns
            (r"three.?pillars|Three.?Pillars", "Three pillars of observability", "Good: observability", Severity.INFO),
            (r"golden.?signals|Golden.?Signals", "Golden signals", "Good: golden signals", Severity.INFO),
            (r"red.?method|RED.?Method", "RED method", "Good: RED method", Severity.INFO),
            (r"use.?method|USE.?Method", "USE method", "Good: USE method", Severity.INFO),
            (r"four.?golden.?signals|Four.?Golden.?Signals", "Four golden signals", "Good: four golden signals", Severity.INFO),
            # Deployment patterns
            (r"blue.?green|Blue.?Green.?Deployment", "Blue-green deployment", "Good: blue-green deployment", Severity.INFO),
            (r"canary|Canary.?Deployment", "Canary deployment", "Good: canary deployment", Severity.INFO),
            (r"rolling|Rolling.?Deployment", "Rolling deployment", "Good: rolling deployment", Severity.INFO),
            (r"feature.?flag|Feature.?Flag", "Feature flags", "Good: feature flags", Severity.INFO),
            (r"dark.?launch|Dark.?Launch", "Dark launch", "Good: dark launch", Severity.INFO),
            (r"shadow|Shadow.?Traffic", "Shadow traffic", "Good: shadow traffic", Severity.INFO),
            (r"a/b|A/B.?Testing", "A/B testing", "Good: A/B testing", Severity.INFO),
            # Data patterns
            (r"event.?sourcing|Event.?Sourcing", "Event sourcing", "Good: event sourcing", Severity.INFO),
            (r"CQRS|Command.?Query.?Responsibility.?Segregation", "CQRS", "Good: CQRS", Severity.INFO),
            (r"saga|Saga", "Saga pattern", "Good: saga pattern", Severity.INFO),
            (r"choreography|Choreography", "Choreography", "Good: choreography", Severity.INFO),
            (r"orchestration|Orchestration", "Orchestration", "Good: orchestration", Severity.INFO),
            (r"outbox|Outbox", "Transactional outbox", "Good: transactional outbox", Severity.INFO),
            (r"event.?carry.?state.?flag|Event.?Carry.?State.?Flag", "Event carry state flag", "Good: event carry state flag", Severity.INFO),
            # Integration patterns
            (r"message.?router|Message.?Router", "Message router", "Good: message router", Severity.INFO),
            (r"content.?enricher|Content.?Enricher", "Content enricher", "Good: content enricher", Severity.INFO),
            (r"content.?filter|Content.?Filter", "Content filter", "Good: content filter", Severity.INFO),
            (r"message.?filter|Message.?Filter", "Message filter", "Good: message filter", Severity.INFO),
            (r"splitter|Splitter", "Splitter pattern", "Good: splitter pattern", Severity.INFO),
            (r"aggregator|Aggregator", "Aggregator pattern", "Good: aggregator pattern", Severity.INFO),
            (r"resequencer|Resequencer", "Resequencer pattern", "Good: resequencer pattern", Severity.INFO),
            (r"correlation.?id|Correlation.?ID", "Correlation ID", "Good: correlation ID", Severity.INFO),
            (r"message.?id|Message.?ID", "Message ID", "Good: message ID", Severity.INFO),
            # Resilience patterns
            (r"circuit.?breaker|Circuit.?Breaker", "Circuit breaker", "Good: circuit breaker", Severity.INFO),
            (r"bulkhead|Bulkhead", "Bulkhead pattern", "Good: bulkhead pattern", Severity.INFO),
            (r"retry|Retry", "Retry pattern", "Good: retry pattern", Severity.INFO),
            (r"fallback|Fallback", "Fallback pattern", "Good: fallback pattern", Severity.INFO),
            (r"timeout|Timeout", "Timeout pattern", "Good: timeout pattern", Severity.INFO),
            (r"rate.?limiter|Rate.?Limiter", "Rate limiter", "Good: rate limiter", Severity.INFO),
            (r"throttler|Throttler", "Throttler pattern", "Good: throttler pattern", Severity.INFO),
            (r"load.?shedder|Load.?Shedder", "Load shedder", "Good: load shedder", Severity.INFO),
            # Security patterns
            (r"defense.?in.?depth|Defense.?in.?Depth", "Defense in depth", "Good: defense in depth", Severity.INFO),
            (r"least.?privilege|Least.?Privilege", "Least privilege", "Good: least privilege", Severity.INFO),
            (r"zero.?trust|Zero.?Trust", "Zero trust", "Good: zero trust", Severity.INFO),
            (r"segmentation|Segmentation", "Network segmentation", "Good: network segmentation", Severity.INFO),
            (r"encryption.?at.?rest|Encryption.?at.?Rest", "Encryption at rest", "Good: encryption at rest", Severity.INFO),
            (r"encryption.?in.?transit|Encryption.?in.?Transit", "Encryption in transit", "Good: encryption in transit", Severity.INFO),
            # Monitoring patterns
            (r"three.?pillars|Three.?Pillars", "Three pillars of observability", "Good: observability", Severity.INFO),
            (r"golden.?signals|Golden.?Signals", "Golden signals", "Good: golden signals", Severity.INFO),
            (r"red.?method|RED.?Method", "RED method", "Good: RED method", Severity.INFO),
            (r"use.?method|USE.?Method", "USE method", "Good: USE method", Severity.INFO),
            (r"four.?golden.?signals|Four.?Golden.?Signals", "Four golden signals", "Good: four golden signals", Severity.INFO),
            # Deployment patterns
            (r"blue.?green|Blue.?Green.?Deployment", "Blue-green deployment", "Good: blue-green deployment", Severity.INFO),
            (r"canary|Canary.?Deployment", "Canary deployment", "Good: canary deployment", Severity.INFO),
            (r"rolling|Rolling.?Deployment", "Rolling deployment", "Good: rolling deployment", Severity.INFO),
            (r"feature.?flag|Feature.?Flag", "Feature flags", "Good: feature flags", Severity.INFO),
            (r"dark.?launch|Dark.?Launch", "Dark launch", "Good: dark launch", Severity.INFO),
            (r"shadow|Shadow.?Traffic", "Shadow traffic", "Good: shadow traffic", Severity.INFO),
            (r"a/b|A/B.?Testing", "A/B testing", "Good: A/B testing", Severity.INFO),
        ]
        for line_num, line in enumerate(lines, 1):
            stripped = line.strip()
            if stripped.startswith('#') or stripped.startswith('//'):
                continue
            for pattern, message, severity in patterns:
                if re.search(pattern, line, re.IGNORECASE):
                    issues.append(self._create_issue(
                        file_path=file_path, line=line_num, message=message,
                        suggestion=message, severity=severity, code_snippet=stripped,
                    ))
        return issues
