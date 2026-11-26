# Module audit — report quality, first pass

Scope: existing modules; no new network requests or discovery capabilities added. Synthetic regression fixtures only.

| Module | Review |
| --- | --- |
| ai_signatures | Fingerprints indicate likely tooling, not a vulnerability; accuracy benchmark pending. |
| cors_wildcard | Reflected origins require context; wildcard is not proof of credentialed browser access. |
| env_leak | Variable-name pattern is a candidate, not a verified credential. |
| firebase_open | Response body no longer printed; response classification still requires application policy and structured response validation. |
| firebase_rules | Textual patterns are review observations, not proof of authorization. |
| headers_audit | Missing headers are hardening observations; framing and CORS interpretation corrected. |
| js_secrets | Public markers separated from secret candidates; raw matched values omitted. Token claims are not cryptographically verified. |
| sourcemap_exposed | Source map availability alone does not establish confidential-source exposure; review pending. |
| storage_bucket_public | Listing availability does not prove private object access; review pending. |
| supabase_columns | Redacted output omits row values and IDs; counts and column labels remain. |
| supabase_enum | Redacted output omits row values; observed anonymous reads require policy context; reports consolidate same base/table across both modules. |

Review observations are not confirmed vulnerabilities. Some textual observations are console-only. The original explicit raw-data mode remains for the Supabase table modules; use redaction and review output before sharing. Redaction is not a universal sanitizer across the entire scanner. Existing network scan behavior is unchanged. No live targets were tested during this update.

## Report triage follow-up

Anonymous-read observations with reported sensitive column names are assigned high **potential** severity and medium confidence, with `REVIEW_REQUIRED` status. Other anonymous-read observations remain informational. The strongest existing column-count metadata survives deduplication regardless of module order. Neither the presence of a column name nor an anonymous read proves that private values are accessible contrary to the expected policy. The terminal and exports expose review status separately. No new probes, table enumeration, or data retrieval added.
