# Successor START namespace reachability review

The PR changes the production coordinator's durable START lookup, the protected authorization reader, and their mocked tests. It changes no application source, dependency lockfile, frontend content glob, Dockerfile, or runtime packaging rule. The ordinary release START remains immutable; an exact successor release ID now selects its own record.

On 2026-10-13, OSV Scanner 2.6.0 ran unfiltered with the repository's recursive, no-resolve procedure. The local report SHA-256 was `21f34e147d0a0791dd961385a2fbe88a1ace201324c18a69d498dc90beb22f56`. The failed hosted audit's unfiltered report SHA-256 was `89db110482f483311c6e4d064fd08215b4a3bc1e2e1366504685c06200bf2073`. Both report the same sole finding: dev-only `braces@3.0.3`, `GHSA-vfj7-8cjw-p6xm` / `CVE-2026-93687`. Neither scan reported a new runtime finding.

The exact-branch canonical browser build completed with 204 packages and excluded `braces@3.0.3`. Runtime packaging checks passed. The reviewed executable/build-input SHA-256 is `00e273d2042be620c9adc9af0107a195ccbd81460c9e4e493c6dd650c2e856a4`. The existing acceptance remains limited to frontend build-only non-runtime use, owner `@T-ej2003`, expiry 2026-11-02. This review renews only the binding to the changed executable inputs; CI must independently repeat the audit on the final head.
