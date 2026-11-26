# Security Graph Engine (SGE)

Offline architecture review from a local JSON model. No extra dependencies, network requests or AI API.

```bash
python -m core.security_graph lab/architecture.json
python -m unittest discover -s tests -p test_security_graph.py -v
```

Schema 1: `components` contain `id`, `kind`, `zone`, `classification`; `relationships` contain `source`, `target`, `relation`, `control`. See the synthetic example in `lab/architecture.json`. The graph lists trust-zone crossings, declared enforcement and review items. A declared server control is not evidence of effective authorization; a review item is not a confirmed vulnerability.

This is the first SGE milestone. Automatic source ingestion and controlled experimental validation are not implemented yet. Existing AIScan CLI and modules are unchanged.
