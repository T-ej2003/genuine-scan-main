# MSCQR

Production-grade, multi-tenant QR issuance, controlled-print, verification, anomaly-detection, and auditability platform.

Zebra ZT410 raw TCP validation and DB-backed print lifecycle notes are documented in
[`documents/ZEBRA_ZT410_DB_BACKED_PRINTING.md`](documents/ZEBRA_ZT410_DB_BACKED_PRINTING.md).


## 1. What This System Is

MSCQR is designed for anti-counterfeit operations across four user types:

- Super Admin: platform owner across all licensees.
- Licensee Admin: tenant operator for one licensee/brand.
- Manufacturer: scoped production user who prints assigned batches.
- Customer: public verifier who checks the MSCQR record for a product label and can report suspicious products.

Core outcome:

- Every QR code is generated, assigned, printed, scanned, and audited with strict server-side state control.
- High-risk behavior (multi-scan, geo drift, velocity spikes) is detected and can trigger automatic blocking policies.
- Batch-level immutable audit exports can be generated for compliance/investigation.



## 4. Architecture

Frontend:

- React 18 + TypeScript + Vite
- React Router + TanStack Query
- Tailwind + Shadcn/Radix
- Recharts for dashboard visuals

Backend:

- Express + TypeScript
- Prisma + PostgreSQL
- JWT auth + role checks + tenant isolation middleware
- SSE for realtime dashboard/event streams

High-level flow:

1. Super Admin allocates QR inventory to a licensee.
2. Licensee Admin creates/assigns batches to manufacturers.
3. Manufacturer creates direct-print jobs and issues one-time render tokens via authenticated print agent.
4. Customer scans signed token (`/scan?t=...`) or verifies by code (`/verify/:code`).
5. System logs events, computes risk/SLA metrics, applies policy controls, and supports immutable audit export.

