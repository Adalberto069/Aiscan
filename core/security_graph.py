"""Offline architecture model. No requests, credentials or exploit execution.

Input describes an application's components and declared trust relationships.
A review item is a hypothesis, not proof of a vulnerability.
"""
import argparse
import json
import re
from dataclasses import asdict, dataclass
from pathlib import Path

_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,79}")
KINDS = {"client", "identity", "api", "database", "storage", "service"}
ZONES = {"untrusted", "application", "data", "external"}
RELATIONS = {"calls", "authenticates", "reads", "writes", "stores"}
CONTROLS = {"server", "client", "none", "unknown"}
CLASSIFICATIONS = {"public", "private", "restricted", "unknown"}


def _choice(value, choices, field):
    if not isinstance(value, str) or value not in choices:
        raise ValueError(f"{field}: expected one of {', '.join(sorted(choices))}")
    return value


def _id(value, field):
    if not isinstance(value, str) or not _ID.fullmatch(value):
        raise ValueError(f"{field}: invalid identifier")
    return value


def _records(value, field):
    if not isinstance(value, list) or any(not isinstance(x, dict) for x in value):
        raise ValueError(f"{field}: expected list of objects")
    return value


@dataclass(frozen=True)
class Component:
    id: str
    kind: str
    zone: str
    classification: str


@dataclass(frozen=True)
class Relationship:
    source: str
    target: str
    relation: str
    control: str


class SecurityGraph:
    def __init__(self, components, relationships):
        self.components = {c.id: c for c in components}
        self.relationships = tuple(relationships)

    @classmethod
    def from_dict(cls, spec):
        if not isinstance(spec, dict) or type(spec.get("schema")) is not int or spec["schema"] != 1:
            raise ValueError("expected architecture schema version 1")
        nodes, seen = [], set()
        for row in _records(spec.get("components"), "components"):
            key = _id(row.get("id"), "component.id")
            if key in seen:
                raise ValueError(f"duplicate component: {key}")
            seen.add(key)
            nodes.append(Component(
                key, _choice(row.get("kind"), KINDS, "component.kind"),
                _choice(row.get("zone"), ZONES, "component.zone"),
                _choice(row.get("classification", "unknown"), CLASSIFICATIONS,
                        "component.classification")))
        if not nodes:
            raise ValueError("at least one component is required")
        edges, edge_keys = [], set()
        for row in _records(spec.get("relationships"), "relationships"):
            source = _id(row.get("source"), "relationship.source")
            target = _id(row.get("target"), "relationship.target")
            if source not in seen or target not in seen:
                raise ValueError("relationship references an unknown component")
            relation = _choice(row.get("relation"), RELATIONS, "relationship.relation")
            control = _choice(row.get("control", "unknown"), CONTROLS, "relationship.control")
            key = (source, target, relation)
            if key in edge_keys:
                raise ValueError(f"duplicate relationship: {key}")
            edge_keys.add(key)
            edges.append(Relationship(source, target, relation, control))
        return cls(nodes, edges)

    def analyze(self):
        """Summarize declared boundaries and missing/uncertain policy documentation."""
        boundaries, review = [], []
        coverage = {"server": 0, "client": 0, "none": 0, "unknown": 0}
        for edge in sorted(self.relationships, key=lambda e: (e.source, e.target, e.relation)):
            source, target = self.components[edge.source], self.components[edge.target]
            if source.zone != target.zone:
                boundaries.append({**asdict(edge), "from_zone": source.zone, "to_zone": target.zone})
            if target.classification not in {"private", "restricted", "unknown"}:
                continue
            if edge.relation not in {"calls", "reads", "writes", "stores"}:
                continue
            coverage[edge.control] += 1
            if target.classification == "unknown":
                code = "DATA_CLASSIFICATION_UNKNOWN"
            elif edge.control == "unknown":
                code = "ENFORCEMENT_UNKNOWN"
            elif edge.control in {"client", "none"}:
                code = "POLICY_REVIEW_REQUIRED"
            else:
                continue
            review.append({"code": code, "status": "REVIEW_REQUIRED",
                           "basis": "declared_model_only", **asdict(edge)})
        total = sum(coverage.values())
        return {"schema": 1, "analysis": "offline_declared_architecture",
                "components": [asdict(c) for c in sorted(self.components.values(), key=lambda c: c.id)],
                "relationships": [asdict(e) for e in sorted(self.relationships,
                    key=lambda e: (e.source, e.target, e.relation))],
                "trust_boundaries": boundaries, "review_items": review,
                "metrics": {"components": len(self.components),
                            "relationships": len(self.relationships),
                            "trust_boundaries": len(boundaries),
                            "review_items": len(review),
                            "protected_or_unclassified_relationships": total,
                            "declared_controls": coverage},
                "limitations": ["Input is an architecture declaration, not live evidence.",
                                "Declared server controls do not prove effective authorization.",
                                "Review items are not confirmed vulnerabilities."]}


def main(argv=None):
    parser = argparse.ArgumentParser(description="AIScan SGE: offline architecture model")
    inputs = parser.add_mutually_exclusive_group(required=True)
    inputs.add_argument("model", nargs="?", type=Path, help="local JSON architecture model")
    inputs.add_argument("--source", type=Path, help="inventory local source dependencies")
    args = parser.parse_args(argv)
    try:
        if args.source is not None:
            from core.source_inventory import inventory
            result = inventory(args.source)
        else:
            spec = json.loads(args.model.read_text(encoding="utf-8-sig"))
            result = SecurityGraph.from_dict(spec).analyze()
    except (OSError, ValueError) as exc:
        parser.exit(2, f"SGE: {exc}\n")
    print(json.dumps(result, indent=2, ensure_ascii=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
