# pygments-lexer-yara-l

[Package](https://img.shields.io/pypi/v/pygments-lexer-yara-l.svg)](https://pypi.org/project/pygments-lexer-yara-l/)
[![PyPI - Downloads](https://img.shields.io/pypi/dm/pygments-lexer-yara-l?color=blue)](https://pypistats.org/packages/pygments-lexer-yara-l)

A [Pygments](https://pygments.org/) plugin providing syntax highlighting for
[YARA-L 2.0](https://cloud.google.com/chronicle/docs/detection/yara-l-2-0-overview),
a language used to create detection rules for Google Security Operations (SecOps).

## Features

- Syntax highlighting for all YARA-L 2.0 constructs
- Supports section keywords (`rule`, `meta`, `events`, `match`, `outcome`, `condition`, `options`, `order`, `limit`, `stage`, `dedup`, `select`, `unselect`)
- Supports operator keywords (`and`, `or`, `not`, `nocase`, `over`, `before`, `after`, `of`, `in`, `any`, `all`, `if`, `regex`, `cidr`, `by`, `asc`, `desc`, `AND`, `OR`)
- Supports boolean/null constants (`true`, `false`, `null`)
- Highlights all built-in namespaced functions (`strings.*`, `re.*`, `math.*`, `net.*`, `timestamp.*`, `arrays.*`, `cast.*`, `hash.*`, `bytes.*`, `window.*`, `metrics.*`, `optimization.*`)
- Highlights aggregate functions (`count`, `count_distinct`, `sum`, `avg`, `max`, `min`, `stddev`, `array`, `array_distinct`, `group`)
- Highlights UDM/graph field paths (`$e.principal.hostname` → variable + attribute tokens)
- Handles all string types: double-quoted strings with escape sequences, back-quoted raw strings, and regex literals
- Handles line comments (`//`) and block comments (`/* */`)
- Auto-detection heuristics based on common YARA-L patterns
- Registered as a Pygments plugin via `pygments.lexers` entry point

## Installation

```bash
pip install pygments-lexer-yara-l
```

## Usage

Once installed, the lexer is automatically available to Pygments via the plugin
entry point. You can use it with any Pygments-compatible tool.

### Command line (pygmentize)

```bash
pygmentize -l yaral my_rule.yaral
pygmentize -l yara-l my_rule.yaral
```

### Python API

```python
from pygments import highlight
from pygments.formatters import TerminalFormatter
from pygments_lexer_yaral import YaraLLexer

code = open('my_rule.yaral').read()
print(highlight(code, YaraLLexer(), TerminalFormatter()))
```

### Terminal preview

```bash
python preview.py
DEBUG=1 python preview.py   # Print each token and its type
```

### Visual preview server

```bash
pip install 'pygments-lexer-yara-l[server]'
python server.py
# Then open http://localhost:8080
```

### MkDocs

Install `pygments-lexer-yara-l` alongside MkDocs. The lexer is picked up
automatically via the Pygments plugin entry point, so no extra configuration is
required. Use the `yaral` language identifier in fenced code blocks:

````markdown
```yaral
rule example {
  events:
    $e.metadata.event_type = "NETWORK_CONNECTION"
  condition:
    $e
}
```
````

### Sphinx

Install `pygments-lexer-yara-l` in the same environment as Sphinx. The lexer
registers itself automatically, so it is available in `code-block` directives
without any additional configuration:

```rst
.. code-block:: yaral

   rule example {
     events:
       $e.metadata.event_type = "NETWORK_CONNECTION"
     condition:
       $e
   }
```

### Flask

Use Pygments directly to render highlighted HTML and serve it from a Flask
route:

```python
from flask import Flask, Markup
from pygments import highlight
from pygments.formatters import HtmlFormatter
from pygments_lexer_yaral import YaraLLexer

app = Flask(__name__)
formatter = HtmlFormatter()

@app.route("/highlight")
def highlight_rule():
    code = open("my_rule.yaral").read()
    highlighted = highlight(code, YaraLLexer(), formatter)
    css = f"<style>{formatter.get_style_defs('.highlight')}</style>"
    return css + highlighted
```

### Django

Add Pygments to your Django project and call it from a view or template tag:

```python
# views.py
from django.utils.safestring import mark_safe
from pygments import highlight
from pygments.formatters import HtmlFormatter
from pygments_lexer_yaral import YaraLLexer

formatter = HtmlFormatter()

def highlight_rule(request):
    from django.shortcuts import render
    code = open("my_rule.yaral").read()
    highlighted = highlight(code, YaraLLexer(), formatter)
    css = formatter.get_style_defs(".highlight")
    return render(request, "highlight.html", {
        "css": mark_safe(css),
        "code": mark_safe(highlighted),
    })
```

```html
{# highlight.html #}
<style>{{ css }}</style>
{{ code }}
```

## Supported aliases

| Alias    | Description             |
|----------|-------------------------|
| `yaral`  | Primary alias           |
| `yara-l` | Alternative alias       |

## File extension

`.yaral`

## MIME type

`text/x-yaral`

## Development

```bash
git clone https://github.com/seanthegeek/pygments-lexer-yara-l.git
cd pygments-lexer-yara-l
pip install -e ".[dev,server]"
make test
```

## License

MIT License. See [LICENSE](LICENSE) for details.

## Links

- [YARA-L 2.0 Overview](https://cloud.google.com/chronicle/docs/detection/yara-l-2-0-overview)
- [YARA-L 2.0 Documentation](https://docs.cloud.google.com/chronicle/docs/yara-l/getting-started)
- [Google Security Operations](https://cloud.google.com/chronicle)
- [Pygments](https://pygments.org/)
- [GitHub Repository](https://github.com/seanthegeek/pygments-lexer-yara-l)
- [Bug Tracker](https://github.com/seanthegeek/pygments-lexer-yara-l/issues)
- [Changelog](CHANGELOG.md)
