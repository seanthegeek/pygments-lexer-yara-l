"""Pygments lexer for YARA-L 2.0."""

import re

from pygments.lexer import RegexLexer, words
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
    'window',
    'any',
    'all',
    'if',
    'regex',
    'cidr',
    'by',
    'tumbling',
    'sliding',
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

            # Event/placeholder/outcome variables: $name or #name
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

            # Punctuation
            (r'[(){}\[\],;:.]', Punctuation),

            # Identifiers (UDM field chains, plain names, etc.)
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
