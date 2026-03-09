# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.0] - 2026-03-08

### Added

- Initial release of the `pygments-lexer-yara-l` package
- `YaraLLexer` lexer with alias `yaral`, additional alias `yara-l`, filename extension `.yaral`, and MIME type `text/x-yaral`
- Auto-detection heuristics based on common YARA-L patterns
- Token classification for section keywords (`rule`, `meta`, `events`, `match`, `outcome`, `condition`, `options`, `order`, `limit`, `stage`, `dedup`, `select`, `unselect`), operator keywords, boolean/null constants, built-in namespaced functions, aggregate functions, operators, punctuation, string literals, numeric literals, line comments, and block comments
- UDM and graph field path highlighting: variable prefix (`$e`, `#e`) classified as `Name.Variable`, dotted path (`.principal.hostname`) classified as `Name.Attribute`
- Standalone dotted field paths without a variable prefix (e.g. `principal.hostname`) classified as `Name.Attribute`
- Dashboard query syntax support: bare field paths, `order:`/`limit:` sections, `stage` blocks, `dedup:`/`select:`/`unselect:` sections
- Full `metrics.*` function set for Risk Analytics rules
- Reference list variables (`%name`) classified as `Name.Variable.Global`

[0.1.0]: https://github.com/seanthegeek/pygments-lexer-yara-l/releases/tag/v0.1.0
