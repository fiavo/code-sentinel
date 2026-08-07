"""
Encoding, I/O, and serialization patterns.
"""
import re
from ..core.models import CodeIssue, Severity, IssueCategory
from ..core.rules import BaseRule


class EncodingIORules(BaseRule):
    @property
    def name(self) -> str:
        return "encoding_io"
    @property
    def description(self) -> str:
        return "Encoding, I/O, and serialization patterns"
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
            # Encoding
            (r"utf-8|UTF-8|utf8|UTF8|ascii|ASCII|latin-1|latin1|ISO-8859-1|cp1252|cp437|gb2312|gbk|gb18030|big5|shift_jis|euc-jp|euc-kr|iso-2022-jp|iso-2022-kr|iso-8859-\d+|windows-\d+|cp\d+|koi8-[ru]", "Encoding", "Good: encoding", Severity.INFO),
            (r"encoding=|charset=", "Encoding parameter", "Good: encoding parameter", Severity.INFO),
            (r"encode\(|decode\(|encodeToByteArray\(|decodeToString\(|encodeToString\(|fromUtf8|toUtf8|fromLatin1|toLatin1|fromBase64|toBase64|base64\.encode|base64\.decode", "Encoding function", "Good: encoding function", Severity.INFO),
            # I/O
            (r"open\(|read\(|write\(|close\(|flush\(|seek\(|tell\(|truncate\(|readline\(|readlines\(|writelines\(|readFile\(|writeFile\(|appendFile\(", "File I/O", "Good: file I/O", Severity.INFO),
            (r"with\s+open\(|with\s+.*as\s+\w+:|try-with-resources|use\s*\(|\.use\s*\{|\.use\s*\(|FileInputStream|FileOutputStream|BufferedReader|BufferedWriter|InputStreamReader|OutputStreamWriter|FileReader|FileWriter", "Resource management", "Good: resource management", Severity.INFO),
            (r"stdin|stdout|stderr|STDIN|STDOUT|STDERR|sys\.stdin|sys\.stdout|sys\.stderr|process\.stdin|process\.stdout|process\.stderr|console\.log|console\.error|console\.warn", "Standard I/O", "Good: standard I/O", Severity.INFO),
            (r"input\(\)|raw_input\(|readline\(\)", "User input", "Good: user input", Severity.INFO),
            (r"print\(|println\(|eprintln\(|printf\(|fprintf\(|fmt\.Print|fmt\.Println|fmt\.Printf|log\.Print|log\.Println|log\.Printf|console\.log|console\.error|console\.warn|cout\s*<<|std::cout|std::cerr", "Output", "Good: output", Severity.INFO),
            # Serialization
            (r"json\.dump|json\.load|json\.dumps|json\.loads|JSON\.stringify|JSON\.parse|serde_json::to|serde_json::from|json.Marshal|json.Unmarshal|json_encode|json_decode|jsonSerialize|jsonDeserialize", "JSON", "Good: JSON serialization", Severity.INFO),
            (r"yaml\.dump|yaml\.load|yaml\.safe_load|yaml\.safe_dump|yaml\.dump_all|yaml\.load_all|to_yaml|from_yaml|serde_yaml::to|serde_yaml::from|yaml.Marshal|yaml.Unmarshal|yaml_encode|yaml_decode", "YAML", "Good: YAML serialization", Severity.INFO),
            (r"toml\.dump|toml\.load|toml\.loads|toml\.dumps|to_toml|from_toml|serde_toml::to|serde_toml::from|toml.Marshal|toml.Unmarshal|toml_encode|toml_decode", "TOML", "Good: TOML serialization", Severity.INFO),
            (r"xml\.dump|xml\.load|xml\.etree|lxml|etree|ElementTree|SAX|DOM|JAXB|XmlSerializer|XmlParser|xml_encode|xml_decode|xml_parse|xml_serialize|xml_deserialize", "XML", "Good: XML serialization", Severity.INFO),
            (r"pickle\.dump|pickle\.load|pickle\.dumps|pickle\.loads|marshal\.dump|marshal\.load|shelve|shelve\.open", "Python serialization", "Good: Python serialization", Severity.INFO),
            (r"bson\.dump|bson\.load|msgpack|protobuf|thrift|avro|flatbuffers|capnproto|CBOR|Ion|Parquet|Arrow|Feather|ORC", "Binary serialization", "Good: binary serialization", Severity.INFO),
            (r"MessagePack|Protocol.?Buffers|FlatBuffers|Cap'n.?Proto|Avro|Thrift|BSON|CBOR|ION|Parquet|Arrow|Feather|ORC", "Binary format", "Good: binary format", Severity.INFO),
            # Compression
            (r"gzip|GZIP|deflate|DEFLATE|brotli|BROTLI|zstd|ZSTD|lz4|LZ4|snappy|SNAPPY|xz|XZ|bz2|BZ2|zlib|ZLIB|compress|Compress|decompress|Decompress", "Compression", "Good: compression", Severity.INFO),
            (r"zlib\.compress|zlib\.decompress|gzip\.open|gzip\.compress|gzip\.decompress|bz2\.open|bz2\.compress|bz2\.decompress|lzma\.open|lzma\.compress|lzma\.decompress|zipfile|tarfile", "Python compression", "Good: Python compression", Severity.INFO),
            (r"zlib|Zlib|ZLIB|flate2|flate|gzip|Gzip|GZIP|brotli|Brotli|BROTLI|zstd|Zstd|ZSTD|lz4|Lz4|LZ4|snappy|Snappy|SNAPPY|xz|Xz|XZ|bz2|Bz2|BZ2", "Compression library", "Good: compression library", Severity.INFO),
            # HTTP
            (r"GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS|TRACE|CONNECT", "HTTP method", "Good: HTTP method", Severity.INFO),
            (r"Content-Type|Accept|Authorization|User-Agent|Cache-Control|Set-Cookie|Cookie|X-Requested-With|X-Forwarded-For|X-Real-IP|X-API-Key|Bearer", "HTTP header", "Good: HTTP header", Severity.INFO),
            (r"200|201|204|301|302|304|400|401|403|404|405|409|410|422|429|500|502|503|504", "HTTP status", "Good: HTTP status", Severity.INFO),
            (r"Content-Type:\s+application/json|Content-Type:\s+text/html|Content-Type:\s+text/plain|Content-Type:\s+multipart/form-data|Content-Type:\s+application/x-www-form-urlencoded|Content-Type:\s+application/xml|Content-Type:\s+text/xml|Content-Type:\s+application/octet-stream", "MIME type", "Good: MIME types", Severity.INFO),
            # WebSocket
            (r"WebSocket|websocket|ws://|wss://|onopen|onmessage|onerror|onclose|send\(|close\(", "WebSocket", "Good: WebSocket", Severity.INFO),
            # gRPC
            (r"grpc|gRPC|proto|protobuf|\.proto|service\s+\w+\s*\{|rpc\s+\w+\s*\(|message\s+\w+\s*\{|enum\s+\w+\s*\{|import\s+", "gRPC/protobuf", "Good: gRPC/protobuf", Severity.INFO),
            # Database I/O
            (r"cursor\.execute|cursor\.fetchone|cursor\.fetchall|cursor\.fetchmany|cursor\.rowcount|cursor\.lastrowid|cursor\.description|connection\.commit|connection\.rollback|connection\.close", "Database cursor", "Good: database cursor", Severity.INFO),
            (r"SELECT\s+\w+\s+FROM|INSERT\s+INTO|UPDATE\s+\w+\s+SET|DELETE\s+FROM|CREATE\s+TABLE|DROP\s+TABLE|ALTER\s+TABLE|CREATE\s+INDEX|DROP\s+INDEX", "SQL query", "Good: SQL query", Severity.INFO),
            # Network I/O
            (r"socket\.connect|socket\.bind|socket\.listen|socket\.accept|socket\.send|socket\.recv|socket\.close|socket\.shutdown", "Socket I/O", "Good: socket I/O", Severity.INFO),
            (r"ssl\.wrap_socket|ssl\.SSLContext|ssl\.create_default_context|ssl\.PROTOCOL_TLS|ssl\.PROTOCOL_TLSv1_2|ssl\.PROTOCOL_TLSv1_3|ssl\.CERT_REQUIRED|ssl\.CERT_OPTIONAL|ssl\.CERT_NONE", "SSL/TLS", "Good: SSL/TLS", Severity.INFO),
            # Async I/O
            (r"asyncio\.open_connection|asyncio\.start_server|aiohttp|httpx|aiofiles|aiomysql|aiopg|aioredis|motor|tornado\.httpclient|tornado\.iostream", "Async I/O", "Good: async I/O", Severity.INFO),
            (r"tokio::io|tokio::fs|tokio::net|tokio::sync|tokio::time|tokio::process|AsyncRead|AsyncWrite|AsyncBufRead|AsyncSeek|AsyncReadExt|AsyncWriteExt|AsyncBufReadExt|AsyncSeekExt", "Rust async I/O", "Good: Rust async I/O", Severity.INFO),
            (r"io\.Reader|io\.Writer|io\.Closer|io\.ReadWriter|io\.ReadCloser|io\.WriteCloser|io\.ReadWriteCloser|io\.ReaderAt|io\.WriterAt|io\.ReaderFrom|io\.WriterTo|io\.StringReader|io\.strings\.NewReader|io\.bytes\.NewBuffer|io\.bytes\.NewReader|bufio\.NewReader|bufio\.NewWriter|bufio\.NewReadWriter", "Go I/O", "Good: Go I/O", Severity.INFO),
            # File formats
            (r"\.json|\.yaml|\.yml|\.toml|\.xml|\.csv|\.tsv|\.ini|\.cfg|\.conf|\.properties|\.env|\.log|\.txt|\.md|\.rst|\.html|\.css|\.js|\.ts|\.jsx|\.tsx|\.py|\.rb|\.go|\.rs|\.java|\.kt|\.swift|\.cpp|\.c|\.h|\.hpp|\.cs|\.php", "File extension", "Good: file formats", Severity.INFO),
            # Binary formats
            (r"\.pdf|\.doc|\.docx|\.xls|\.xlsx|\.ppt|\.pptx|\.odt|\.ods|\.odp|\.rtf|\.epub|\.mobi|\.azw|\.djvu|\.tex|\.latex|\.bib", "Document format", "Good: document formats", Severity.INFO),
            (r"\.png|\.jpg|\.jpeg|\.gif|\.bmp|\.ico|\.svg|\.webp|\.tiff|\.tif|\.raw|\.psd|\.ai|\.eps|\.pdf", "Image format", "Good: image formats", Severity.INFO),
            (r"\.mp3|\.mp4|\.wav|\.flac|\.aac|\.ogg|\.wma|\.avi|\.mkv|\.mov|\.wmv|\.flv|\.webm|\.m4v|\.m4a|\.opus|\.midi|\.mid", "Media format", "Good: media formats", Severity.INFO),
            (r"\.zip|\.tar|\.gz|\.bz2|\.xz|\.7z|\.rar|\.tgz|\.tar\.gz|\.tar\.bz2|\.tar\.xz|\.zipx", "Archive format", "Good: archive formats", Severity.INFO),
            (r"\.exe|\.dll|\.so|\.dylib|\.a|\.lib|\.o|\.obj|\.bin|\.elf|\.mach-o|\.pe|\.coff|\.class|\.jar|\.war|\.ear", "Binary format", "Good: binary formats", Severity.INFO),
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
