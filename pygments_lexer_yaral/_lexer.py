"""Pygments lexer for YARA-L 2.0."""

import re

from pygments.lexer import RegexLexer, bygroups, words
from pygments.token import (
    Comment,
    Keyword,
    Name,
    Number,
    Operator,
    Punctuation,
    String,
    Whitespace,
)

# Section keywords
SECTION_KEYWORDS = (
    'rule',
    'meta',
    'events',
    'match',
    'outcome',
    'condition',
    'options',
    'order',
    'limit',
    'stage',
    'dedup',
    'select',
    'unselect',
)

# Operator/flow keywords
OPERATOR_KEYWORDS = (
    'and',
    'or',
    'not',
    'nocase',
    'over',
    'before',
    'after',
    'of',
    'in',
    'any',
    'all',
    'if',
    'regex',
    'cidr',
    'by',
    'asc',
    'desc',
    'AND',
    'OR',
)

# Boolean and null constants
CONSTANTS = (
    'true',
    'false',
    'null',
)

# Built-in functions from YARA-L 2.0 documentation
BUILTIN_FUNCTIONS = (
    'arrays.concat',
    'arrays.contains',
    'arrays.index_to_float',
    'arrays.index_to_int',
    'arrays.index_to_str',
    'arrays.join_string',
    'arrays.length',
    'arrays.max',
    'arrays.min',
    'arrays.size',
    'bytes.to_base64',
    'cast.as_bool',
    'cast.as_float',
    'cast.as_int',
    'cast.as_string',
    'hash.fingerprint2011',
    'hash.sha256',
    'math.abs',
    'math.ceil',
    'math.floor',
    'math.geo_distance',
    'math.is_increasing',
    'math.log',
    'math.pow',
    'math.random',
    'math.round',
    'math.sqrt',
    'net.ip_in_range_cidr',
    'optimization.sample_rate',
    're.capture',
    're.capture_all',
    're.regex',
    're.replace',
    'strings.base64_decode',
    'strings.coalesce',
    'strings.concat',
    'strings.contains',
    'strings.count_substrings',
    'strings.ends_with',
    'strings.extract_domain',
    'strings.extract_hostname',
    'strings.from_base64',
    'strings.from_hex',
    'strings.ltrim',
    'strings.reverse',
    'strings.rtrim',
    'strings.split',
    'strings.to_lower',
    'strings.to_upper',
    'strings.trim',
    'strings.url_decode',
    'metrics.alert_event_name_count',
    'metrics.auth_attempts_fail',
    'metrics.auth_attempts_success',
    'metrics.auth_attempts_total',
    'metrics.dns_bytes_outbound',
    'metrics.dns_queries_fail',
    'metrics.dns_queries_success',
    'metrics.dns_queries_total',
    'metrics.file_executions_fail',
    'metrics.file_executions_success',
    'metrics.file_executions_total',
    'metrics.http_queries_fail',
    'metrics.http_queries_success',
    'metrics.http_queries_total',
    'metrics.network_bytes_inbound',
    'metrics.network_bytes_outbound',
    'metrics.network_bytes_total',
    'metrics.resource_creation_success',
    'metrics.resource_creation_total',
    'metrics.resource_deletion_success',
    'metrics.resource_read_fail',
    'metrics.resource_read_success',
    'timestamp.as_unix_seconds',
    'timestamp.current_seconds',
    'timestamp.get_date',
    'timestamp.get_day_of_week',
    'timestamp.get_hour',
    'timestamp.get_minute',
    'timestamp.get_timestamp',
    'timestamp.get_week',
    'timestamp.now',
    'window.avg',
    'window.first',
    'window.last',
    'window.median',
    'window.mode',
    'window.range',
    'window.stddev',
    'window.variance',
)

# Aggregate functions used in outcome/condition sections
AGGREGATE_FUNCTIONS = (
    'count',
    'count_distinct',
    'sum',
    'avg',
    'max',
    'min',
    'stddev',
    'array',
    'array_distinct',
    'group',
)


class YaraLLexer(RegexLexer):
    """Lexer for YARA-L 2.0, a language used to create detection rules for
    Google Security Operations (SecOps).
    """

    name = 'YARA-L'
    aliases = ['yaral', 'yara-l']
    filenames = ['*.yaral']
    mimetypes = ['text/x-yaral']
    url = 'https://cloud.google.com/chronicle/docs/detection/yara-l-2-0-overview'

    tokens = {
        'root': [
            # Whitespace
            (r'\s+', Whitespace),

            # Line comments
            (r'//.*?\n', Comment.Single),

            # Block comments
            (r'/\*', Comment.Multiline, 'block_comment'),

            # Back-quoted (raw) strings
            (r'`', String.Single, 'backtick_string'),

            # Double-quoted strings
            (r'"', String.Double, 'double_string'),

            # Regular expression literals /pattern/
            (r'/(?:[^/\\\n]|\\.)+/', String.Regex),

            # Built-in namespaced functions (must come before plain identifiers)
            (words(BUILTIN_FUNCTIONS, suffix=r'\b'), Name.Builtin),

            # Section keywords
            (words(SECTION_KEYWORDS, suffix=r'\b'), Keyword),

            # Operator keywords
            (words(OPERATOR_KEYWORDS, suffix=r'\b'), Keyword.Pseudo),

            # Constants
            (words(CONSTANTS, suffix=r'\b'), Keyword.Constant),

            # Aggregate functions (plain names used as functions in outcome/condition)
            (words(AGGREGATE_FUNCTIONS, suffix=r'\b'), Name.Builtin),

            # Standalone UDM/graph field paths (no variable prefix): principal.hostname
            # Must come after builtins so namespaced functions are matched first.
            (r'[a-zA-Z_]\w*(?:\.[a-zA-Z_]\w*)+', Name.Attribute),

            # Variable with UDM/graph field path: $login.metadata.event_type
            (r'([\$#][a-zA-Z_][a-zA-Z0-9_]*)((?:\.[a-zA-Z_]\w*)+)',
             bygroups(Name.Variable, Name.Attribute)),

            # Simple event/placeholder variables without path: $name or #name
            (r'[\$#][a-zA-Z_][a-zA-Z0-9_]*', Name.Variable),

            # Reference lists: %name
            (r'%[a-zA-Z_][a-zA-Z0-9_.]*', Name.Variable.Global),

            # Float literals (before integer to avoid partial match)
            (r'\b\d+\.\d+', Number.Float),

            # Integer literals
            (r'\b\d+', Number.Integer),

            # Operators
            (r'!=|<=|>=|[=<>!]', Operator),
            (r'[+\-*/%|~^]', Operator),

            # Punctuation (dot handled separately via UDM path rules above)
            (r'[(){}\[\],;:]', Punctuation),
            (r'\.', Punctuation),

            # Identifiers: plain names
            (r'[a-zA-Z_][a-zA-Z0-9_]*', Name),
        ],

        'block_comment': [
            (r'[^*/]+', Comment.Multiline),
            (r'\*/', Comment.Multiline, '#pop'),
            (r'[*/]', Comment.Multiline),
        ],

        'double_string': [
            (r'\\[nrtbf\\"\'0]', String.Escape),
            (r'\\.', String.Escape),
            (r'"', String.Double, '#pop'),
            (r'[^"\\]+', String.Double),
        ],

        'backtick_string': [
            (r'`', String.Single, '#pop'),
            (r'[^`]+', String.Single),
        ],
    }

    def analyse_text(self, text: str) -> float:
        """Return a score based on how likely this text is YARA-L."""
        score = 0.0
        # Rule definition pattern
        if re.search(r'\brule\s+\w+\s*\{', text):
            score += 0.7
        # Section keywords followed by colon
        if re.search(r'\b(meta|events|match|outcome|condition|options)\s*:', text):
            score += 0.3
        return min(score, 1.0)
