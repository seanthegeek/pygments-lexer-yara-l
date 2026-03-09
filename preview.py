#!/usr/bin/env python3
"""Terminal preview of the YARA-L lexer.

Usage:
    python preview.py                 # Pretty-print using Terminal256 formatter
    DEBUG=1 python preview.py         # Print each token and its type
"""

import os
import sys

from pygments import highlight
from pygments.formatters import Terminal256Formatter
from pygments.styles import get_style_by_name

from pygments_lexer_yaral import YaraLLexer

SAMPLE_PATH = 'tests/examplefiles/sample.yaral'
DEBUG = os.environ.get('DEBUG')

sample = open(SAMPLE_PATH).read()
lexer = YaraLLexer()

if DEBUG:
    for index, tokentype, value in lexer.get_tokens_unprocessed(sample):
        print(f'{tokentype!s:<45} {value!r}')
else:
    print(highlight(sample, lexer, Terminal256Formatter(style=get_style_by_name('material'))))
