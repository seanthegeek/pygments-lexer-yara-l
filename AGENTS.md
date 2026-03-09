# AGENTS.md

This file provides guidance to AI coding agents when working with code in this
repository.

## Project overview

`pygments-lexer-yara-l` is a Python package that provides a Pygments syntax
highlighting lexer for YARA-L 2.0, the detection rule language used by Google
Security Operations (SecOps).

- **Language**: YARA-L 2.0
- **Short name / primary alias**: `yaral`
- **Additional alias**: `yara-l`
- **File extension**: `.yaral`
- **MIME type**: `text/x-yaral`
- **Lexer class**: `YaraLLexer` in `pygments_lexer_yaral/_lexer.py`
- **Language URL**: <https://cloud.google.com/chronicle/docs/detection/yara-l-2-0-overview>

## Repository layout

```
pygments_lexer_yaral/
    __init__.py          # Exports YaraLLexer
    _lexer.py            # The Pygments RegexLexer implementation
tests/
    test_lexer.py        # pytest test suite
    examplefiles/
        demo.yaral       # Short demo rule (5-15 lines), zero error tokens
        sample.yaral     # Comprehensive visual sample (50-200 lines), zero error tokens
preview.py               # Terminal preview script
server.py                # Flask-based HTML preview server
pyproject.toml           # Build metadata and entry points
Makefile                 # make test / make server
```

## Development workflow

### Install in editable mode

```bash
pip install -e ".[dev,server]"
```

### Run tests

```bash
make test
# or
pytest -v
```

### Terminal preview

```bash
python preview.py
DEBUG=1 python preview.py   # Print each token and its type
```

### Visual preview server

```bash
make server
# Then open http://localhost:8080
```

## Lexer design rules

### Token type mapping

| Construct | Pygments token |
| --- | --- |
| Section keywords (`rule`, `meta`, `events`, `match`, `outcome`, `condition`, `options`) | `Keyword` |
| Operator keywords (`and`, `or`, `not`, `nocase`, `over`, `before`, `after`, `of`, `in`, `window`, `any`, `all`, `if`, `regex`, `cidr`, `by`, `tumbling`, `sliding`) | `Keyword.Pseudo` |
| Boolean/null constants (`true`, `false`, `null`) | `Keyword.Constant` |
| Built-in namespaced functions (e.g. `strings.concat`, `re.regex`) | `Name.Builtin` |
| Aggregate functions (`count`, `count_distinct`, `sum`, `avg`, `max`, `min`, `stddev`, `array`, `array_distinct`) | `Name.Builtin` |
| UDM/graph field paths after a variable (`$e.principal.hostname`, `$e.metadata.event_type`) — the dotted path portion | `Name.Attribute` |
| Standalone dotted field paths without a variable prefix (`principal.hostname`) | `Name.Attribute` |
| Unrecognized identifiers | `Name` |
| Arithmetic/comparison operators | `Operator` |
| Brackets, commas, semicolons, colons, dots, pipes | `Punctuation` |
| Integer literals | `Number.Integer` |
| Float literals | `Number.Float` |
| Double-quoted strings | `String.Double` |
| Back-quoted raw strings | `String.Single` |
| Regex literals (`/pattern/`) | `String.Regex` |
| Escape sequences inside strings | `String.Escape` |
| Line comments (`//`) | `Comment.Single` |
| Block comments (`/* */`) | `Comment.Multiline` |
| Event/placeholder variables (`$name`, `#name`) | `Name.Variable` |
| Reference lists (`%name`) | `Name.Variable.Global` |

### Critical implementation notes

- The `analyze_text` method **must** have the signature
  `def analyze_text(self, text: str) -> float:` — a regular instance method with
  `self` and a return type annotation. Do **not** use `@staticmethod`.
- Built-in namespaced functions **must** be matched before UDM path patterns so that
  `strings.concat` is classified as `Name.Builtin` rather than `Name.Attribute`.
- UDM/graph field paths (`$e.principal.hostname`, `$whois.graph.entity.hostname`) are
  tokenized with `bygroups`: the `$var` portion is `Name.Variable` and the dotted path
  (e.g. `.principal.hostname`) is `Name.Attribute`. Standalone dotted paths without a
  variable prefix also emit `Name.Attribute`.
- IP address patterns must use plain `r'\.'` — do **not** add a negative lookahead.
- Do **not** add `for` as a keyword (that is a YARA keyword, not YARA-L).
- All module-level keyword/function/constant tuples are passed to
  `words(..., suffix=r'\b')` inline inside the `tokens` dict.

### Zero error-token requirement

Both `tests/examplefiles/demo.yaral` and `tests/examplefiles/sample.yaral`
must produce **zero** `Error` tokens and the concatenated token values must
exactly reconstruct the original source text.

When modifying the lexer:

1. Run `DEBUG=1 python preview.py` to inspect token assignments.
2. Fix any patterns that emit `Error` tokens.
3. Re-run `pytest -v` until all tests pass.

## Adding new keywords or functions

1. Add the new item to the appropriate module-level tuple in `_lexer.py`.
2. Add at least one example to `tests/examplefiles/sample.yaral`.
3. Run `pytest -v` to confirm zero error tokens.

## Language reference

- Overview: <https://cloud.google.com/chronicle/docs/detection/yara-l-2-0-overview>
- Getting started: <https://docs.cloud.google.com/chronicle/docs/yara-l/getting-started>
- Meta syntax: <https://docs.cloud.google.com/chronicle/docs/yara-l/meta-syntax>
- Events syntax: <https://docs.cloud.google.com/chronicle/docs/yara-l/events-syntax>
- Match syntax: <https://docs.cloud.google.com/chronicle/docs/yara-l/match-syntax>
- Outcome syntax: <https://docs.cloud.google.com/chronicle/docs/yara-l/outcome-syntax>
- Condition syntax: <https://docs.cloud.google.com/chronicle/docs/yara-l/condition-syntax>
- Options syntax: <https://docs.cloud.google.com/chronicle/docs/yara-l/options-syntax>
- Expressions: <https://docs.cloud.google.com/chronicle/docs/yara-l/expressions>
- Functions: <https://docs.cloud.google.com/chronicle/docs/yara-l/functions>
- Examples: <https://docs.cloud.google.com/chronicle/docs/yara-l/yara-l-2-0-examples>
