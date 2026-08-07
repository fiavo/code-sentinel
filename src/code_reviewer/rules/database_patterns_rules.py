"""
Database patterns for SQL and NoSQL.
"""

import re
from typing import Optional

from ..core.models import CodeIssue, Severity, IssueCategory
from ..core.rules import BaseRule


class DatabasePatternsRules(BaseRule):
    """Database pattern detection."""

    @property
    def name(self) -> str:
        return "database_patterns"

    @property
    def description(self) -> str:
        return "Database pattern detection"

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
            # SQL patterns
            (r"(?:SELECT|INSERT|UPDATE|DELETE|CREATE|ALTER|DROP|TRUNCATE|INDEX|VIEW)", "SQL operation", "Good: using SQL", Severity.INFO),
            (r"(?:JOIN|LEFT|RIGHT|INNER|OUTER|CROSS|FULL)", "SQL join", "Good: using SQL joins", Severity.INFO),
            (r"(?:WHERE|AND|OR|NOT|IN|BETWEEN|LIKE|IS|NULL|EXISTS|ANY|ALL|SOME)", "SQL condition", "Good: using SQL conditions", Severity.INFO),
            (r"(?:GROUP|BY|ORDER|HAVING|LIMIT|OFFSET|UNION|INTERSECT|EXCEPT|DISTINCT)", "SQL clause", "Good: using SQL clauses", Severity.INFO),
            (r"(?:COUNT|SUM|AVG|MIN|MAX|COALESCE|NULLIF|IFNULL|IF|CASE|WHEN|THEN|ELSE|END)", "SQL function", "Good: using SQL functions", Severity.INFO),
            (r"(?:BEGIN|COMMIT|ROLLBACK|SAVEPOINT|RELEASE|START|SET)", "Transaction control", "Good: using transactions", Severity.INFO),
            (r"(?:AUTO_INCREMENT|SERIAL|IDENTITY|SEQUENCE|DEFAULT|NOT|NULL|PRIMARY|KEY|FOREIGN|UNIQUE|CHECK|INDEX|CONSTRAINT|REFERENCES)", "Schema definition", "Good: defining schema", Severity.INFO),
            (r"(?:VARCHAR|CHAR|TEXT|BLOB|CLOB|NCHAR|NVARCHAR|BINARY|VARBINARY|BOOLEAN|BIT|TINYINT|SMALLINT|INT|INTEGER|BIGINT|FLOAT|DOUBLE|DECIMAL|NUMERIC|DATE|TIME|DATETIME|TIMESTAMP|INTERVAL|JSON|JSONB|XML|UUID|ARRAY|ENUM|SET|GEOMETRY|POINT|LINESTRING|POLYGON|MULTIPOINT|MULTILINESTRING|MULTIPOLYGON|GEOMETRYCOLLECTION)", "Data type", "Good: using data types", Severity.INFO),
            (r"(?:DATABASE|SCHEMA|TABLE|VIEW|INDEX|PROCEDURE|FUNCTION|TRIGGER|EVENT|GRANT|REVOKE)", "Database object", "Good: using database objects", Severity.INFO),
            (r"(?:EXPLAIN|ANALYZE|DESCRIBE|SHOW|USE|SET|RESET|PREPARE|EXECUTE|DEALLOCATE|LOCK|UNLOCK|FLUSH|PURGE|OPTIMIZE|REPAIR|CHECK|ANALYZE|VACUUM|REINDEX|CLONE|IMPORT|EXPORT)", "Database administration", "Good: using database commands", Severity.INFO),
            (r"(?:connection.*pool|pool.*size|max.*connections|idle.*timeout|connection.*timeout|reconnect|retry|failover|load.*balance|read.*replica|write.*primary|sharding|partitioning|replication|backup|restore|point.*time.*recovery|wal|archive|log.*shipping)", "Connection management", "Good: managing connections", Severity.INFO),
            (r"(?:migration|alembic|flyway|liquibase|django\.db\.migrations|prisma\.migrate|typeorm|knex|sequelize|drizzle|pgm)", "Database migration", "Good: using migrations", Severity.INFO),

            # NoSQL patterns
            (r"(?:MongoDB|Cassandra|DynamoDB|CouchDB|Redis|Memcached|Elasticsearch|Neo4j|RethinkDB|ArangoDB|RavenDB|Firebase|Firestore|Supabase|PlanetScale|TiDB|CockroachDB|YugabyteDB|Vitess|ProxySQL|MaxScale)", "NoSQL/NewSQL database", "Good: using modern databases", Severity.INFO),

            # ORM patterns
            (r"(?:ORM|model\.save|model\.delete|model\.update|model\.create|model\.find|model\.filter|model\.query|model\.all|model\.get|model\.first|model\.count|model\.exists|model\.aggregate|model\.bulk_create|model\.bulk_update|model\.prefetch|model\.select_related|model\.annotate|model\.values|model\.values_list|model\.only|model\.defer|model\.select_for_update|model\.create_many|model\.update_many|model\.delete_many|model\.upsert|model\.bulk_upsert)", "ORM operations", "Good: using ORM", Severity.INFO),

            # Caching
            (r"(?:cache|redis|memcached|APC|OPcache|Varnish|Nginx|CDN|edge.*cache|browser.*cache|service.*worker|workbox|sw-precache)", "Caching strategy", "Good: using caching", Severity.INFO),

            # Monitoring
            (r"(?:monitor|metrics|prometheus|grafana|datadog|new.relic|app.dynamics|dynatrace|splunk|ELK|kibana|jaeger|zipkin|opentelemetry|openmetrics|statsd|graphite|collectd|telegraf|fluentd|fluentbit|logstash|filebeat|metricbeat|heartbeat|packetbeat|apm)", "Monitoring/Observability", "Good: monitoring system", Severity.INFO),
        ]

        for line_num, line in enumerate(lines, 1):
            stripped = line.strip()
            if stripped.startswith('#') or stripped.startswith('--'):
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
