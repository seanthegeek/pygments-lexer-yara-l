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

## Key Patterns

- The lexer registers tag `yaral` with aliases `yara-l` and `chronicle`.
- Keyword/function sets are defined as class-level `Set` objects with memoization (`@keywords ||= Set.new`).
- Tests assert that lexing demo/sample files produces no `Error` tokens and reconstructs the original input exactly (lossless round-trip).
- When adding new YARA-L keywords or functions, update both the lexer sets and the visual sample file to ensure test coverage.

## Official YARA-L documentation (use ONLY these — do not guess syntax)

**MANDATORY: Before writing or modifying the lexer, you MUST fetch and read every URL in this list.** This is not background reading — it is a required prerequisite step. Fetch each page, extract the function or command names, and verify them against the lexer before declaring any work complete.

Do not use the quick-reference or overview pages as a substitute for the individual detail pages. The quick-reference pages omit aliases, secondary functions, and command-specific keywords that only appear on the detail pages. Every page in this list exists because it contains information not fully captured elsewhere.

- Get started <https://docs.cloud.google.com/chronicle/docs/yara-l/getting-started>
- Meta section <https://docs.cloud.google.com/chronicle/docs/yara-l/meta-syntax>
- Events section <https://docs.cloud.google.com/chronicle/docs/yara-l/events-syntax>
- Match section <https://docs.cloud.google.com/chronicle/docs/yara-l/match-syntax>
- Outcome section <https://docs.cloud.google.com/chronicle/docs/yara-l/outcome-syntax>
- Conditions section <https://docs.cloud.google.com/chronicle/docs/yara-l/condition-syntax>
- Options section <https://docs.cloud.google.com/chronicle/docs/yara-l/options-syntax>
- Expressions, operators, and other constructs <https://docs.cloud.google.com/chronicle/docs/yara-l/expressions>
- Nested if statements <https://docs.cloud.google.com/chronicle/docs/yara-l/nested-if>
- Use OR syntax in the condition section <https://docs.cloud.google.com/chronicle/docs/yara-l/multievent-or>
- Use N OF syntax with event variables <https://docs.cloud.google.com/chronicle/docs/yara-l/multievent-n-of>
- Repeated fields <https://docs.cloud.google.com/chronicle/docs/yara-l/repeated-fields>
- Reference list syntax <https://docs.cloud.google.com/chronicle/docs/yara-l/reference-list-syntax>
- Detection event sampling <https://docs.cloud.google.com/chronicle/docs/yara-l/detection-event-sampling>
- Functions <https://docs.cloud.google.com/chronicle/docs/yara-l/functions>
- Statistics and aggregations <https://docs.cloud.google.com/chronicle/docs/investigation/statistics-aggregations-in-udm-search>
- Use conditions in Search and Dashboards <https://docs.cloud.google.com/chronicle/docs/investigation/yara-l-2-0-conditions>
- Create and save visualizations in Search <https://docs.cloud.google.com/chronicle/docs/reports/visualization-in-search>
- Use metrics in Search <https://docs.cloud.google.com/chronicle/docs/investigation/yara-l-2-0-metrics-search>
- Use deduplication in Search and Dashboards <https://docs.cloud.google.com/chronicle/docs/investigation/deduplication-yaral>
- Create multi-stage queries <https://docs.cloud.google.com/chronicle/docs/investigation/multi-stage-yaral>
- Use context-enriched data in rules <https://docs.cloud.google.com/chronicle/docs/detection/use-enriched-data-in-rules>
- Context-aware analysis overview <https://docs.cloud.google.com/chronicle/docs/detection/context-aware-analytics>
- Specify entity risk score in rules <https://docs.cloud.google.com/chronicle/docs/detection/yara-l-entity-risk-score>
- Use metric functions for Risk Analytics rules <https://docs.cloud.google.com/chronicle/docs/detection/metrics-functions>
- Applied Threat Intelligence fusion feed overview <https://docs.cloud.google.com/chronicle/docs/detection/ati-fusion-feed>
- Composite detections overview <https://docs.cloud.google.com/chronicle/docs/detection/composite-detections>
- Construct composite detection rules <https://docs.cloud.google.com/chronicle/docs/yara-l/composite-detection-rules>
- Rule structure and best practices <https://docs.cloud.google.com/chronicle/docs/detection/yara-l-best-practices>
- Run a rule against historical data <https://docs.cloud.google.com/chronicle/docs/detection/run-rule-historical-data>
- Configure rule exclusions <https://docs.cloud.google.com/chronicle/docs/detection/rule-exclusions>
- View and troubleshoot rule errors <https://docs.cloud.google.com/chronicle/docs/detection/rule-errors>
- Known issues and limitations <https://docs.cloud.google.com/chronicle/docs/detection/yara-l-issues>
- Examples: YARA-L 2.0 queries <https://docs.cloud.google.com/chronicle/docs/yara-l/yara-l-2-0-examples>
- Sample YARA-L 2.0 queries for dashboards <https://docs.cloud.google.com/chronicle/docs/reference/sample-yaral-for-native-dashboard>
- Transition from SPL to YARA-L 2.0 <https://docs.cloud.google.com/chronicle/docs/yara-l/transition_spl_yaral>

### Fetching Google docs pages

Google docs pages are JavaScript-rendered SPAs. Normal `curl` or `WebFetch` calls return empty/nav-only content. You **must** use the Googlebot User-Agent to get rendered content:

```bash
curl -s -H 'User-Agent: Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)' '<URL>'
```

### Important context

YARA-L 2.0 is used in three contexts within Google SecOps, and the lexer must handle all of them:

1. **Detection rules** — structured rules.
2. **Search queries** — UDM search with statistical/aggregation keywords
3. **Dashboard queries** — similar to search queries but with dashboard-specific functions  and a required `match` section.
