# QR Allocation Validation Worksheet

## Current implementation note

Repo evidence shows existing allocation logic in `backend/src/services/qrAllocationService.ts` with transaction-scoped advisory locking and prefix-based QR generation.

## Validate before launch

- Licensee prefix is correct and approved
- Start number and end number are correct
- Quantity matches commercial approval
- No overlap with any previous allocation
- Reserved ranges are documented
- Batch assignment destination is correct
- Audit trail is present after allocation

## Evidence

- allocation request ID:
- approving user:
- validation date:
- screenshot or export:
- issues found:
