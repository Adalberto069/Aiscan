"""Local review of explicit PostgreSQL RLS toggles in one migration file.

Not a SQL executor or parser for arbitrary PostgreSQL. No network access.
Results describe statements, not live database state.
"""
import argparse
import json
import re
from pathlib import Path

# Quoted bodies/comments are consumed before matching SQL statements.
_TOKEN = re.compile(
    r"(?P<space>\s+)|(?P<line>--[^\n]*)|(?P<block>/\*)|"
    r"(?P<dollar>\$(?:[A-Za-z_][A-Za-z_0-9]*)?\$)|"
    r"""(?P<literal>'(?:''|[^'])*')|(?P<quoted>"(?:""|[^"])*")|"""
    r"(?P<word>[A-Za-z_][A-Za-z_0-9$]*)|(?P<other>.)",
    re.DOTALL,
)
_IDENT = r'(?:[a-z_][a-z_0-9$]*|"(?:[^"]|"")+")'
_TOGGLE = re.compile(
    rf"alter table (?:if exists )?(?:only )?({_IDENT}(?: \. {_IDENT})?) "
    r"(enable|disable) row level security"
)
MAX_BYTES = 1024 * 1024


def _statements(sql):
    """Yield tokenized top-level statements with start lines; skip opaque bodies."""
    pos = 0
    line = 1
    parts = []
    start = 1
    while pos < len(sql):
        match = _TOKEN.match(sql, pos)
        kind = match.lastgroup
        raw = match.group()
        end = match.end()
        if kind == "literal" and "\\" in raw:
            raise ValueError("backslash in SQL literal is outside supported syntax")
        if kind == "block":
            depth = 1
            while depth:
                marker = re.search(r"/\*|\*/", sql[end:])
                if marker is None:
                    raise ValueError("unterminated block comment")
                depth += 1 if marker.group() == "/*" else -1
                end += marker.end()
        elif kind == "dollar":
            close = sql.find(raw, end)
            if close < 0:
                raise ValueError("unterminated dollar body")
            end = close + len(raw)
        elif kind == "other" and raw in ("'", '"', "\\"):
            raise ValueError("unsupported or unterminated SQL literal")
        if kind not in ("space", "line", "block"):
            if not parts:
                start = line
            if raw == ";":
                yield " ".join(parts), start
                parts = []
            elif kind in ("literal", "dollar"):
                parts.append("<opaque>")
            else:
                parts.append(raw.lower() if kind == "word" else raw)
        line += sql.count("\n", pos, end)
        pos = end
    if parts:
        yield " ".join(parts), start


def review(sql):
    """Report each recognized explicit DISABLE, with later ENABLE noted."""
    if len(sql.encode("utf-8")) > MAX_BYTES:
        raise ValueError("SQL input exceeds 1 MiB")
    states = {}
    for statement, line in _statements(sql):
        match = _TOGGLE.fullmatch(statement)
        if match:
            table, action = match.groups()
            states[table] = (action, line)
    findings = [
        {"rule": "PG-RLS-EXPLICIT-DISABLE", "table": table, "line": line,
         "severity": "HIGH_POTENTIAL", "status": "REVIEW_REQUIRED",
         "message": "Last recognized explicit RLS toggle in this file disables RLS."}
        for table, (action, line) in sorted(states.items()) if action == "disable"
    ]
    return {"findings": findings, "recognized_tables": len(states),
            "limitations": [
                "Static review of one file only; not proof of deployed state or exposure.",
                "Ignores dynamic SQL, multi-action statements, and transaction outcomes.",
                "Table spellings are compared lexically; search_path, quoted aliases and renames are not resolved.",
                "Does not evaluate privileges, policy expressions, or other migrations.",
                "No findings does not establish that RLS is enabled.",
            ]}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("file", type=Path, help="Local PostgreSQL migration SQL")
    args = parser.parse_args()
    try:
        if not args.file.is_file():
            raise ValueError("expected a regular file")
        with args.file.open("rb") as stream:
            raw = stream.read(MAX_BYTES + 1)
        if len(raw) > MAX_BYTES:
            raise ValueError("SQL input exceeds 1 MiB")
        result = review(raw.decode("utf-8-sig"))
    except (OSError, ValueError) as exc:
        parser.error(str(exc))
    print(json.dumps(result, ensure_ascii=True, indent=2))


if __name__ == "__main__":
    main()
