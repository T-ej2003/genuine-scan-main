# Stage B receipt-bound adoption

Receipt-bound adoption is an explicit recovery path for completed Stage-B outputs whose original local preparation or checker-authorization files are unavailable. It reads the exact versioned reservation, intent, and result objects in the Stage-B apply-attempt namespace, authenticates the historical links retained in those receipts, and independently checks the existing task definitions or terminal policy/Terraform successor.

The output is not reconstructed historical evidence. It records `historicalSignatureVerified: false`, `durableReceiptChainVerified: true`, and `freshIndependentCheckerRequired: true`. It grants no authority to repeat registration or policy mutation. The normal `prepare-registration-adoption` and `prepare-policy-adoption` operations still require their original authenticated files.

Invoke only with `operation: prepare-receipt-bound-adoption` and the two durable transaction identifiers. The executor derives historical source, purpose, and digests from the exact S3 receipts and terminal ownership row; it does not accept caller-supplied historical source data. The operation is read-only and returns current-consumer registration and policy handoffs. Publication preparation re-reads those pinned receipt versions and live successors. Its fresh independent-checker authorization discloses the missing historical files and binds the receipt-chain and live-corroboration digests, current consumer SHA, publication package, saved plan, and expiry.

Registration handoffs also bind the canonical image-impact report and its digest for the historical registration source through the current consumer source. The verifier recomputes that report when consuming the handoff and applies the same compatibility check as normal registration adoption. Publication consumption rechecks Git ancestry for both historical sources; Git errors fail closed. Each historical authorization digest must equal its authorization and transaction ID, as established by the durable receipt chain.

This path does not archive new evidence or change retention policy. Durable evidence archival remains separate post-release work.
