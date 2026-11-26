"""Offline source inventory for SGE. No code execution or network access."""
import ast
import json
import os
from pathlib import Path

SKIP = {".git", ".venv", "venv", "node_modules", "dist", "build", "__pycache__", ".next", "vendor"}
MAX_FILES = 2000
MAX_BYTES = 256 * 1024
MAX_TOTAL = 16 * 1024 * 1024
# Only package identifiers, never source literals, URLs or configuration values.
PACKAGES = {
    "@supabase/supabase-js": ("supabase", "database", "data"),
    "supabase": ("supabase", "database", "data"),
    "firebase": ("firebase", "service", "external"),
    "firebase_admin": ("firebase", "service", "external"),
    "firebase-admin": ("firebase", "service", "external"),
    "react": ("react", "client", "untrusted"),
    "vue": ("vue", "client", "untrusted"),
    "next": ("next", "api", "application"),
    "express": ("express", "api", "application"),
    "fastapi": ("fastapi", "api", "application"),
    "flask": ("flask", "api", "application"),
    "django": ("django", "api", "application"),
    "sqlalchemy": ("sqlalchemy", "database", "data"),
    "psycopg": ("postgresql", "database", "data"),
    "psycopg2": ("postgresql", "database", "data"),
    "sqlite3": ("sqlite", "database", "data"),
    "boto3": ("aws-sdk", "service", "external"),
    "@aws-sdk/client-s3": ("s3", "storage", "external"),
}


def inventory(root):
    root = Path(root).resolve(strict=True)
    if not root.is_dir():
        raise ValueError("source must be a local directory")
    evidence = {}
    counts = {"files_read": 0, "files_skipped": 0, "parse_errors": 0,
              "bytes_read": 0, "limit_reached": False}
    def note(package, path, basis):
        if package in PACKAGES:
            name, kind, zone = PACKAGES[package]
            entry = evidence.setdefault(name, {"kind": kind, "zone": zone,
                                               "observations": set()})
            entry["observations"].add((path.relative_to(root).as_posix(), basis, package))

    for folder, dirs, files in os.walk(root, followlinks=False):
        dirs[:] = sorted(d for d in dirs if d not in SKIP and not d.startswith(".")
                         and not (Path(folder) / d).is_symlink())
        for filename in sorted(files):
            path = Path(folder) / filename
            if filename.startswith(".") or (filename != "package.json" and path.suffix != ".py"):
                continue
            if counts["files_read"] >= MAX_FILES or counts["bytes_read"] >= MAX_TOTAL:
                counts["limit_reached"] = True
                break
            try:
                if path.is_symlink() or not path.is_file() or not path.resolve().is_relative_to(root):
                    counts["files_skipped"] += 1
                    continue
                with path.open("rb") as f:
                    raw = f.read(min(MAX_BYTES, MAX_TOTAL - counts["bytes_read"]) + 1)
                if len(raw) > MAX_BYTES or counts["bytes_read"] + len(raw) > MAX_TOTAL:
                    counts["files_skipped"] += 1
                    continue
                counts["files_read"] += 1
                counts["bytes_read"] += len(raw)
                source = raw.decode("utf-8-sig")
                if filename == "package.json":
                    manifest = json.loads(source)
                    if not isinstance(manifest, dict):
                        raise ValueError("invalid package manifest")
                    for section in ("dependencies", "optionalDependencies", "peerDependencies"):
                        entries = manifest.get(section, {})
                        if isinstance(entries, dict):
                            for name in entries:
                                note(name, path, "declared_dependency")
                else:
                    for node in ast.walk(ast.parse(source)):
                        if isinstance(node, ast.Import):
                            for alias in node.names:
                                note(alias.name.split(".")[0], path, "python_import")
                        elif isinstance(node, ast.ImportFrom) and node.level == 0 and node.module:
                            note(node.module.split(".")[0], path, "python_import")
            except (OSError, UnicodeError, SyntaxError, ValueError, RecursionError):
                counts["parse_errors"] += 1
        if counts["limit_reached"]:
            break

    components = [{"id": name, "kind": entry["kind"], "zone": entry["zone"],
                   "classification": "unknown",
                   "observations": [{"file": p, "basis": b, "package": pkg}
                                    for p, b, pkg in sorted(entry["observations"])]}
                  for name, entry in sorted(evidence.items())]
    return {"schema": 1, "analysis": "offline_source_inventory",
            "components": components, "relationships": [], "metrics": counts,
            "limitations": ["Imports and manifests suggest technologies, not runtime use.",
                            "Relationships and security controls require an explicit architecture model.",
                            "No vulnerability verdicts are inferred from dependencies.",
                            "Supported inputs: Python imports and package.json dependencies."]}
