const {
  PrintItemState,
  PrintJobStatus,
  PrintSessionStatus,
} = require("@prisma/client");
const {
  hasPrintItemPhysicalEvidence,
  isZeroEvidencePrintItemReusable,
  requestedRangeSkipsRecovery,
} = require("../dist/services/printReservationService");

const assert = (condition, message) => {
  if (!condition) throw new Error(message);
};

const abandonedZeroEvidenceItem = (overrides = {}) => ({
  state: PrintItemState.FAILED,
  agentAckedAt: null,
  dispatchedAt: null,
  printConfirmedAt: null,
  confirmationEvidence: null,
  deviceJobRef: null,
  failureReason: "Operator closed unconfirmed failed print run so labels can be started again.",
  deadLetterReason: "operator_abandoned_unconfirmed_run",
  printSession: {
    status: PrintSessionStatus.CANCELLED,
    printJob: { status: PrintJobStatus.CANCELLED },
  },
  ...overrides,
});

const stoppedUnconfirmedItem = (overrides = {}) => ({
  state: PrintItemState.CANCELLED,
  agentAckedAt: new Date("2026-06-18T10:00:00.000Z"),
  dispatchedAt: new Date("2026-06-18T10:00:01.000Z"),
  printConfirmedAt: null,
  confirmationEvidence: null,
  deviceJobRef: "winspool:ZDesigner:42",
  failureReason: "Operator stopped print run after partial physical confirmation.",
  deadLetterReason: "operator_stopped_print_run",
  printSession: {
    status: PrintSessionStatus.STOPPED,
    printJob: { status: PrintJobStatus.PARTIALLY_COMPLETED },
  },
  ...overrides,
});

const run = () => {
  assert(
    isZeroEvidencePrintItemReusable(abandonedZeroEvidenceItem()),
    "Abandoned zero-evidence print items should be reservable again without creating a duplicate PrintItem"
  );

  assert(
    !isZeroEvidencePrintItemReusable(abandonedZeroEvidenceItem({ agentAckedAt: new Date() })),
    "Agent-acknowledged items must not be silently reused"
  );

  assert(
    !isZeroEvidencePrintItemReusable(abandonedZeroEvidenceItem({ dispatchedAt: new Date() })),
    "Dispatched items must not be silently reused"
  );

  assert(
    !isZeroEvidencePrintItemReusable(abandonedZeroEvidenceItem({ printConfirmedAt: new Date() })),
    "Confirmed items must not be silently reused"
  );

  assert(
    !isZeroEvidencePrintItemReusable(abandonedZeroEvidenceItem({ confirmationEvidence: { source: "agent-confirm" } })),
    "Items with confirmation evidence must remain blocked"
  );

  assert(
    isZeroEvidencePrintItemReusable(stoppedUnconfirmedItem()),
    "Stopped unconfirmed print items should be recoverable even when they were dispatched but not confirmed"
  );

  assert(
    !isZeroEvidencePrintItemReusable(stoppedUnconfirmedItem({ printConfirmedAt: new Date() })),
    "Stopped confirmed print items must not be reused"
  );

  assert(
    !isZeroEvidencePrintItemReusable(stoppedUnconfirmedItem({ confirmationEvidence: { source: "connector-confirm" } })),
    "Stopped items with confirmation evidence must not be reused"
  );

  assert(
    !isZeroEvidencePrintItemReusable(abandonedZeroEvidenceItem({ deviceJobRef: "winspool:ZDesigner:42" })),
    "Items with a device job reference must remain blocked"
  );

  assert(
    !isZeroEvidencePrintItemReusable(
      abandonedZeroEvidenceItem({
        failureReason: "Unexpected operator failure",
        deadLetterReason: "unknown_failure",
      })
    ),
    "Only explicit abandon or pre-dispatch failure reasons should be eligible for reuse"
  );

  assert(
    !isZeroEvidencePrintItemReusable(
      abandonedZeroEvidenceItem({
        printSession: { status: PrintSessionStatus.ACTIVE, printJob: { status: PrintJobStatus.PENDING } },
      })
    ),
    "Active sessions should never be reused by a new reservation"
  );

  assert(
    hasPrintItemPhysicalEvidence({ confirmationEvidence: { spooler: "accepted" } }),
    "Non-empty confirmation evidence should count as physical-print evidence"
  );
  assert(
    !hasPrintItemPhysicalEvidence({ confirmationEvidence: {} }),
    "Empty confirmation evidence should not by itself block zero-evidence recovery"
  );

  assert(
    requestedRangeSkipsRecovery({ recoveryStartCode: "QR-000006", rangeStart: "QR-000011", rangeEnd: "QR-000020" }),
    "Explicit later ranges must not skip unresolved stopped-run recovery labels"
  );

  assert(
    !requestedRangeSkipsRecovery({ recoveryStartCode: "QR-000006", rangeStart: "QR-000006", rangeEnd: "QR-000010" }),
    "Recovery range starting at the first unconfirmed code should be allowed"
  );

  assert(
    !requestedRangeSkipsRecovery({ recoveryStartCode: "QR-000006" }),
    "Default batch printing should be allowed to resume from the first unconfirmed code selected by the backend"
  );
};

try {
  run();
} catch (error) {
  console.error(error);
  process.exit(1);
}
