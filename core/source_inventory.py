"""Offline source inventory for SGE. No code execution or network access."""
import ast
import json
import os
import re
import sys
import tomllib
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


# Conservative identifiers; no URLs, version values, or inline credentials.
_NAME = re.compile(r"(?:@[A-Za-z0-9_.-]+/)?[A-Za-z0-9][A-Za-z0-9_.-]{0,127}\Z")
_REQUIREMENT = re.compile(r"^([A-Za-z0-9][A-Za-z0-9_.-]*)(?:\[[A-Za-z0-9_,. -]+\])?\s*(?=$|[<>=!~;#])")
_PY_ALIASES = {"beautifulsoup4": "bs4", "google-generativeai": "google",
               "pyyaml": "yaml", "pillow": "PIL"}


def inventory(root):
    root = Path(root).resolve(strict=True)
    if not root.is_dir():
        raise ValueError("source must be a local directory")
    evidence, links = {}, set()
    counts = {"files_read": 0, "files_skipped": 0, "parse_errors": 0,
              "bytes_read": 0, "limit_reached": False}
    candidates = 0

    def local_module(name):
        return any((base / (name + ".py")).is_file() or (base / name).is_dir()
                   for base in (root, root / "src"))

    def note(package, path, basis, ecosystem):
        if not isinstance(package, str) or not _NAME.fullmatch(package):
            return
        if basis == "python_import":
            if local_module(package):
                links.add((path.relative_to(root).as_posix(), package))
                return
            if package not in PACKAGES and package in sys.stdlib_module_names:
                return
        if ecosystem == "python":
            package = _PY_ALIASES.get(package.lower().replace("_", "-"), package)
        if package in PACKAGES:
            name, kind, zone = PACKAGES[package]
            key = name
        else:
            # Unknown technology is still inventoried, not called a web service.
            name, kind, zone = package, "dependency", "unknown"
            key = ecosystem + ":" + package
        entry = evidence.setdefault(key, {"name": name, "kind": kind, "zone": zone,
                                          "observations": set()})
        entry["observations"].add((path.relative_to(root).as_posix(), basis, package))

    def requirements(rows, path, basis):
        for row in rows:
            if not isinstance(row, str):
                continue
            match = _REQUIREMENT.match(row.strip())
            if match:
                note(match.group(1), path, basis, "python")

    for folder, dirs, files in os.walk(root, followlinks=False):
        dirs[:] = sorted(d for d in dirs if d not in SKIP and not d.startswith(".")
                         and not (Path(folder) / d).is_symlink()
                         and (Path(folder) / d).resolve().is_relative_to(root))
        for filename in sorted(files):
            path = Path(folder) / filename
            is_requirements = filename == "requirements.txt"
            if filename.startswith(".") or (filename not in {"package.json", "pyproject.toml"}
                                             and not is_requirements and path.suffix != ".py"):
                continue
            if candidates >= MAX_FILES or counts["bytes_read"] >= MAX_TOTAL:
                counts["limit_reached"] = True
                break
            candidates += 1
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
                    for section in ("dependencies", "optionalDependencies", "peerDependencies", "devDependencies"):
                        entries = manifest.get(section, {})
                        if isinstance(entries, dict):
                            for name in entries:
                                note(name, path, section, "npm")
                elif filename == "pyproject.toml":
                    project = tomllib.loads(source).get("project", {})
                    if isinstance(project, dict):
                        deps = project.get("dependencies", [])
                        if isinstance(deps, list):
                            requirements(deps, path, "pyproject_dependency")
                elif is_requirements:
                    requirements(source.splitlines(), path, "requirements_dependency")
                else:
                    for node in ast.walk(ast.parse(source)):
                        if isinstance(node, ast.Import):
                            for alias in node.names:
                                note(alias.name.split(".")[0], path, "python_import", "python")
                        elif isinstance(node, ast.ImportFrom) and node.level == 0 and node.module:
                            note(node.module.split(".")[0], path, "python_import", "python")
            except (OSError, UnicodeError, SyntaxError, ValueError, RecursionError):
                counts["parse_errors"] += 1
        if counts["limit_reached"]:
            break

    components = [{"id": key, "name": entry["name"], "kind": entry["kind"], "zone": entry["zone"],
                   "classification": "unknown",
                   "observations": [{"file": p, "basis": b, "package": pkg}
                                    for p, b, pkg in sorted(entry["observations"])]}
                  for key, entry in sorted(evidence.items())]
    source_links = [{"file": p, "module": m, "basis": "local_python_import"}
                    for p, m in sorted(links)]
    counts.update(components=len(components), source_links=len(source_links))
    return {"schema": 1, "analysis": "offline_source_inventory",
            "components": components, "relationships": [], "source_links": source_links,
            "metrics": counts,
            "limitations": ["Imports and manifests suggest technologies, not runtime use.",
                            "Generic Python imports may be unresolved rather than installed dependencies.",
                            "Source links are imports, not runtime trust relationships.",
                            "No vulnerability verdicts are inferred from dependencies.",
                            "Supported inputs: Python imports, requirements.txt, pyproject.toml and package.json."]}
