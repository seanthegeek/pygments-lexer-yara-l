# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.0] - 2026-03-08

### Added

- Initial release of the `pygments-lexer-yara-l` package
- `YaraLLexer` lexer with alias `yaral`, additional alias `yara-l`, filename extension `.yaral`, and MIME type `text/x-yaral`
- Auto-detection heuristics based on common YARA-L patterns
- Token classification for section keywords, operator keywords, boolean/null constants, built-in functions, operators, punctuation, string literals, numeric literals, line comments, and block comments

[0.1.0]: https://github.com/seanthegeek/pygments-lexer-yara-l/releases/tag/v0.1.0
