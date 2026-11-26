# Security Graph Engine (SGE) 0.3

Offline architecture review and source inventory. No new dependencies or AI API.

```bash
python aiscan.py --source .
python aiscan.py --graph lab/architecture.json
python aiscan.py --source . --json inventory.json
python -m unittest discover -s tests -v
```

The original `python -m core.security_graph` commands still produce JSON on stdout. The main CLI prints a readable summary; `--json` creates a new output file without overwriting an existing file. Local modes cannot be combined with network scans.

The inventory recognizes Python imports, requirements.txt, pyproject.toml and package.json dependencies. Unknown packages are listed as unclassified dependencies; local absolute Python imports are separate source references. Standard-library imports are excluded except explicitly classified technologies. Imports and declarations are not proof of installed packages or runtime use. Source references do not establish runtime trust relationships. Evidence consists of identifiers and relative filenames, not source bodies or dependency version values.

The architecture model uses schema 1: components contain id, kind, zone and classification; relationships contain source, target, relation and control. See lab/architecture.json. The graph lists trust-zone crossings, declared enforcement and review items. The inventory output is not an architecture declaration. Review items do not confirm vulnerabilities.

JavaScript/TypeScript source parsing, HTML/SQL analysis, automatic runtime relationship inference and correlation with live scan findings remain unimplemented. Existing network scanner and Lua modules are unchanged.
