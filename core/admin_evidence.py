"""Import owner-provided, aggregate administrative review evidence.
No network, SQL execution, row values, credentials or remote discovery.
Evidence is an operator assertion, not independently verified by this importer.
"""
import json
from pathlib import Path

from core.findings import FindingsStore

_FIELDS = {
    "schema", "project", "anonymous_email_read", "rls_enabled",
    "unconditional_anonymous_policy", "expired_active_count",
    "paid_total", "paid_with_absolute_url",
}
_MAX_BYTES = 16384


def import_evidence(path):
    with Path(path).open("rb") as stream:
        raw = stream.read(_MAX_BYTES + 1)
    if len(raw) > _MAX_BYTES:
        raise ValueError("Evidence file exceeds 16 KiB")
    data = json.loads(raw.decode("utf-8-sig"))
    if not isinstance(data, dict) or set(data) != _FIELDS:
        raise ValueError("Unexpected evidence schema or fields")
    if type(data["schema"]) is not int or data["schema"] != 1:
        raise ValueError("Unsupported schema")
    project = data["project"]
    if not isinstance(project, str) or not 1 <= len(project) <= 80 or not all(
        ch.isascii() and (ch.isalnum() or ch in " ._-") for ch in project
    ):
        raise ValueError("Invalid project label")
    for name in ("anonymous_email_read", "rls_enabled", "unconditional_anonymous_policy"):
        if type(data[name]) is not bool:
            raise ValueError("Expected boolean evidence")
    for name in ("expired_active_count", "paid_total", "paid_with_absolute_url"):
        if type(data[name]) is not int or data[name] < 0:
            raise ValueError("Expected nonnegative aggregate count")
    if data["paid_with_absolute_url"] > data["paid_total"]:
        raise ValueError("Inconsistent aggregate counts")

    store = FindingsStore(project)
    facts = {k: data[k] for k in (
        "anonymous_email_read", "rls_enabled", "unconditional_anonymous_policy")}
    if data["anonymous_email_read"]:
        broad = not data["rls_enabled"] or data["unconditional_anonymous_policy"]
        store.add_dict(
            title="Permissao anonima sobre campo de email",
            severity="ALTA" if broad else "MEDIA", confidence="MEDIA",
            module="admin-evidence", category="admin-privacy-review", cwe="CWE-200",
            verdict="OWNER_EVIDENCE",
            description="Metadados administrativos informados indicam permissao de leitura. "
                        "Revisar politicas restritivas e confirmar expectativa de privacidade. "
                        "Importador nao valida o estado remoto.",
            remediation="Restringir privilegios de coluna e disponibilizar apenas campos publicos.",
            evidence=facts)
    else:
        store.add_dict(title="Permissao anonima de email nao indicada no snapshot",
                       severity="INFO", module="admin-evidence",
                       category="admin-privacy-observation", verdict="OWNER_EVIDENCE",
                       description="Ausencia deste indicador nao garante privacidade.",
                       evidence=facts)
    for field, title, fix in (
        ("expired_active_count", "Licencas vencidas com status ativo",
         "Aplicar a expiracao em todos os caminhos de autorizacao."),
        ("paid_with_absolute_url", "Conteudo pago com URL absoluta cadastrada",
         "Revisar armazenamento e exigir autorizacao antes da entrega."),
    ):
        count = data[field]
        store.add_dict(title=title, severity="MEDIA" if count else "INFO",
                       confidence="MEDIA", module="admin-evidence",
                       category="admin-review-" + field, verdict="OWNER_EVIDENCE",
                       description="Contagem administrativa informada; nao demonstra acesso indevido.",
                       remediation=fix, evidence={"count": count})
    return store
