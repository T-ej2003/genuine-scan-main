# Green backend recovery dependency and OSV review

PR #725 changes the governed backend recovery path and updates dependencies after the 2026-10-24 audit found newly published advisories. The recovery design, Terraform, database migrations, and RLS policy logic are unchanged. `npm run rls:full-generate` produced no tracked artifact diff; the migration-set digest remains `b783cab33f40cddaa8aa9bf3bef3dbbbabb218af5891bbda36eb1724514f8dc9`.

## Runtime reachability and remediation

| Package | Before | After | Dependency path and exposure |
| --- | --- | --- | --- |
| `zod` | 3.25.76 | 4.6.7 | Direct in root and backend. Backend validates attacker-controlled API payloads, so the reported excessive-work path was reachable. The v4 migration uses `issues` and explicit record keys; affected externally controlled arrays gained finite limits. |
| `body-parser` | 1.20.6 | 1.20.9 | Transitive through backend Express. Request bodies are attacker controlled. Express 4.22.3 still requests the older `~1.20.5` line, so a narrow npm override pins the patched version. |
| `multer` | 2.4.0 | 2.5.0 | Direct backend upload parser; attacker-controlled uploads are possible. Patched release installed. |
| `nodemailer` | 10.0.12 | 10.2.1 | Direct backend mail transport. Application-controlled message construction does not justify retaining an advisory-bearing runtime package. Patched release installed. |
| `undici` | 7.30.0 | 7.30.1 | Transitive root tooling dependency via jsdom. The patched lock version removes the reported findings. |

The root lock also pins `@emnapi/core` and `@emnapi/runtime` 1.11.3 as build-only development dependencies. Linux `npm ci` requires these optional wasm-runtime peers; the macOS-generated lock had omitted them and caused CI installation to fail before tests. The repaired lock passed a clean `npm ci --ignore-scripts --no-audit --no-fund` locally.

The root and backend `npm audit --audit-level=high` runs each report zero vulnerabilities. Fresh OSV Scanner 2.6.0 `scan source -r .` returned zero findings; the unfiltered JSON report SHA-256 is `54345d5194d238b6017d0f3181f392109ce35023cc6b4bdfa8c134943dcb578e`. The canonical OSV gate accepts zero exceptions. The reviewed executable-input fingerprint is `ac57c8738a315b90fa05a7ae6dc99d581678ebb3fde23ed277c547f14596d256`.

The browser build, backend build, root typecheck, trust-critical compiled suite, and focused request-parser, MFA, mail, incident, and local-agent protocol tests passed locally. The parser regression test checks bounded Zod validation and that malformed compressed input cannot terminate the HTTP server. Production has not been mutated. If source or lockfiles change again, regenerate the fingerprint and rerun the scanner and canonical gate before relying on this review.
