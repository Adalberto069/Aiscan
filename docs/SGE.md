# Security Graph Engine (SGE) 0.2

Offline architecture review and source inventory. No extra dependencies, network requests or AI API.

```bash
python -m core.security_graph lab/architecture.json
python -m core.security_graph --source .
python -m unittest discover -s tests -v
```

The source inventory recognizes selected Python imports and JavaScript package.json dependencies. It records the relative file path and package as evidence, skips dependency/build directories and dotfiles, and bounds file sizes and total bytes. It does not execute source code, extract literal secrets, infer actual permissions or claim a vulnerability.

The architecture model uses schema 1: components contain id, kind, zone and classification; relationships contain source, target, relation and control. See lab/architecture.json. The graph lists trust-zone crossings, declared enforcement and review items. Declared server controls are not evidence of effective authorization. Review items are not confirmed vulnerabilities.

Automatic technology inventory is implemented; automatic inference of relationships, runtime validation and additional language parsers are not. Existing scanner and Lua modules are unchanged.
