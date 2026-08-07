"""
Data processing and analytics patterns.
"""
import re
from ..core.models import CodeIssue, Severity, IssueCategory
from ..core.rules import BaseRule


class DataProcessingRules(BaseRule):
    @property
    def name(self) -> str:
        return "data_processing"
    @property
    def description(self) -> str:
        return "Data processing and analytics patterns"
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
            # Data processing libraries
            (r"pandas|numpy|scipy|sklearn|scikit-learn|matplotlib|seaborn|plotly|bokeh|altair|statsmodels|scrapy|beautifulsoup|bs4|lxml|selenium|playwright|puppeteer|scrapy|twisted|celery|redis|rabbitmq|kafka|spark|dask|polars|vaex|modin|ray|dask|joblib|multiprocessing|concurrent\.futures|threading|asyncio", "Python data tools", "Good: data tools", Severity.INFO),
            (r"DataFrame|Series|ndarray|matrix|array|DataFrame\.read|DataFrame\.to|DataFrame\.groupby|DataFrame\.merge|DataFrame\.concat|DataFrame\.pivot|DataFrame\.melt|DataFrame\.stack|DataFrame\.unstack|DataFrame\.apply|DataFrame\.map|DataFrame\.transform|DataFrame\.agg|DataFrame\.resample|DataFrame\.rolling|DataFrame\.expanding|DataFrame\.ewm", "Pandas/NumPy", "Good: pandas/numpy", Severity.INFO),
            (r"read_csv|read_excel|read_json|read_sql|read_parquet|read_hdf|read_feather|read_stata|read_sas|read_clipboard|read_html|read_xml|read_pickle|to_csv|to_excel|to_json|to_sql|to_parquet|to_hdf|to_feather|to_stata|to_sas|to_clipboard|to_html|to_xml|to_pickle", "Data I/O", "Good: data I/O", Severity.INFO),
            (r"merge|join|concat|append|insert|update|upsert|bulk_insert|bulk_update|batch|chunk|stream|pipe|pipeline|ETL|ELT|data.?pipeline|DataPipeline|data_pipeline", "Data operations", "Good: data operations", Severity.INFO),
            # SQL patterns
            (r"SELECT.*FROM.*WHERE|INSERT\s+INTO|UPDATE.*SET|DELETE\s+FROM|CREATE\s+TABLE|ALTER\s+TABLE|DROP\s+TABLE|CREATE\s+INDEX|DROP\s+INDEX|CREATE\s+VIEW|DROP\s+VIEW|CREATE\s+FUNCTION|CREATE\s+PROCEDURE|CREATE\s+TRIGGER|CREATE\s+EVENT|CREATE\s+DATABASE|CREATE\s+SCHEMA|GRANT|REVOKE|COMMIT|ROLLBACK|SAVEPOINT|BEGIN|END|IF|ELSE|THEN|LOOP|WHILE|FOR|REPEAT|CASE|WHEN|LIKE|IN|EXISTS|NOT|AND|OR|BETWEEN|IS|NULL|TRUE|FALSE|AS|DISTINCT|GROUP\s+BY|ORDER\s+BY|HAVING|LIMIT|OFFSET|JOIN|LEFT\s+JOIN|RIGHT\s+JOIN|INNER\s+JOIN|OUTER\s+JOIN|CROSS\s+JOIN|FULL\s+JOIN|UNION|INTERSECT|EXCEPT|MINUS|ALL|ANY|SOME|EXISTS|NOT\s+EXISTS|IN|NOT\s+IN|BETWEEN|LIKE|REGEXP|RLIKE|GLOB|MATCH|IS\s+NULL|IS\s+NOT\s+NULL|ISNULL|COALESCE|NULLIF|IFNULL|IF|CASE|WHEN|THEN|ELSE|END|CAST|CONVERT|COALESCE|NULLIF|NVL|NVL2|DECODE|ISNULL|ISNULL|IIF|CHOOSE|GREATEST|LEAST|ABS|CEIL|CEILING|FLOOR|ROUND|TRUNCATE|TRUNC|MOD|POWER|EXP|LOG|LN|LOG10|LOG2|SQRT|SIGN|RAND|RANDOM|UUID|GENERATE_SERIES|GENERATE_SERIES|GENERATE_SERIES|JSON_EXTRACT|JSON_SET|JSON_INSERT|JSON_REPLACE|JSON_REMOVE|JSON_ARRAY|JSON_OBJECT|JSON_ARRAYAGG|JSON_OBJECTAGG|XML_EXTRACT|XML_SET|XML_INSERT|XML_REMOVE|XML_EXISTS|XMLQUERY|XMLTABLE|XMLEXISTS|XMLSERIALIZE|XMLPARSE|XMLAGG", "SQL operations", "Good: SQL operations", Severity.INFO),
            # ETL patterns
            (r"extract|Extract|load|Load|transform|Transform|stage|Stage|mediate|Mediate|conform|Conform|deliver|Deliver|clean|Clean|validate|Validate|enrich|Enrich|aggregate|Aggregate|deduplicate|Deduplicate|normalize|Normalize|denormalize|Denormalize|partition|Partition|shard|Shard|replicate|Replicate|sync|Sync|snapshot|Snapshot|delta|Delta|CDC|cdc|incremental|Incremental|batch|Batch|stream|Stream|real.?time|RealTime", "ETL patterns", "Good: ETL patterns", Severity.INFO),
            (r"Apache\s+Kafka|Kafka|Flink|Flink|Spark|Spark|Airflow|Airflow|Prefect|Prefect|Dagster|Dagster|Luigi|Luigi|NiFi|NiFi|Talend|Talend|Informatica|Informatica|dbt|dbt|Snowflake|Snowflake|BigQuery|BigQuery|Redshift|Redshift|Databricks|Databricks|Dataform|Dataform|Looker|Looker|Tableau|Tableau|PowerBI|PowerBI|Superset|Superset|Metabase|Metabase|Grafana|Grafana|Grafana|Grafana", "Data tools", "Good: data tools", Severity.INFO),
            # Data quality
            (r"data.?quality|DataQuality|data_quality|data.?validation|DataValidation|data_validation|schema.?validation|SchemaValidation|schema_validation|data.?cleaning|DataCleaning|data_cleaning|data.?profiling|DataProfiling|data_profiling|data.?monitoring|DataMonitoring|data_monitoring|data.?governance|DataGovernance|data_governance|data.?lineage|DataLineage|data_lineage|data.?catalog|DataCatalog|data_catalog", "Data quality", "Good: data quality", Severity.INFO),
            (r"GreatExpectations|great_expectations|pytest|pydantic|cerberus|marshmallow|voluptuous|colander|schematics|schema|validictory|jsonschema|JSONSchema|fastjsonschema|cattrs|attrs|dataclasses|pydantic|marshmallow|colander|voluptuous|schematics|cerberus|validictory|schema", "Data validation", "Good: data validation", Severity.INFO),
            # Data storage
            (r"PostgreSQL|Postgres|MySQL|MariaDB|SQLite|SQL\s+Server|Oracle|DB2|MongoDB|Cassandra|DynamoDB|CouchDB|Redis|Memcached|Elasticsearch|OpenSearch|Neo4j|RethinkDB|ArangoDB|RavenDB|Firebase|Firestore|Supabase|PlanetScale|TiDB|CockroachDB|YugabyteDB|Vitess|ProxySQL|MaxScale|ClickHouse|Druid|InfluxDB|TimescaleDB|QuestDB|DuckDB|Parquet|Iceberg|Delta\s+Lake|Hudi", "Data storage", "Good: data storage", Severity.INFO),
            # Data formats
            (r"JSON|yaml|YAML|TOML|XML|CSV|TSV|Parquet|ORC|Avro|Protobuf|FlatBuffers|Cap'n\s+Proto|MessagePack|BSON|CBOR|Arrow|Feather|HDF5|HDFS|S3|GCS|Azure\s+Blobs|MinIO|R2|DigitalOcean\s+Spaces|Wasabi|Backblaze\s+B2|local.?filesystem|local_filesystem", "Data formats", "Good: data formats", Severity.INFO),
            # Data streaming
            (r"Kafka|kafka|Kinesis|kinesis|Pulsar|pulsar|NATS|nats|Redis\s+Streams|redis_streams|RabbitMQ|rabbitmq|ActiveMQ|activemq|IBM\s+MQ|ibm_mq|Amazon\s+SQS|amazon_sqs|Amazon\s+SNS|amazon_sns|Google\s+PubSub|google_pubsub|Azure\s+Service\s+Bus|azure_service_bus|Azure\s+Queue|azure_queue", "Message streaming", "Good: message streaming", Severity.INFO),
            # Data analytics
            (r"analytics|Analytics|analytics|metrics|Metrics|metrics|dashboard|Dashboard|dashboard|visualization|Visualization|visualization|chart|Chart|chart|graph|Graph|graph|plot|Plot|plot|report|Report|report|insight|Insight|insight|reporting|Reporting|reporting|business.?intelligence|BusinessIntelligence|business_intelligence|BI|BI|OLAP|OLAP|OLTP|OLTP", "Data analytics", "Good: data analytics", Severity.INFO),
            # Data pipelines
            (r"Apache\s+Airflow|Airflow|Prefect|Prefect|Dagster|Dagster|Luigi|Luigi|NiFi|NiFi|Talend|Talend|Informatica|Informatica|dbt|dbt|Dataform|Dataform|Matillion|Matillion|Fivetran|Fivetran|Stitch|Stitch|Airbyte|Airbyte|Hevo|Hevo|Segment|Segment|Fivetran|Fivetran", "Data pipeline tools", "Good: data pipeline tools", Severity.INFO),
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
