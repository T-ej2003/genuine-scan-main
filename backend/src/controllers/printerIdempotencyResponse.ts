export const mapPrinterIdempotencyError = (error: unknown) => {
  const message = String((error as any)?.message || "");
  if (message.includes("IDEMPOTENCY_KEY_REQUIRED")) {
    return { status: 400, payload: { success: false, error: "Missing x-idempotency-key header" } };
  }
  if (message.includes("IDEMPOTENCY_KEY_IN_PROGRESS")) {
    return {
      status: 202,
      payload: {
        success: true,
        data: {
          outcome: "pending",
          message: "This printer action is already in progress. Please wait for the current result.",
        },
      },
    };
  }
  if (message.includes("IDEMPOTENCY_KEY_PAYLOAD_MISMATCH")) {
    return { status: 409, payload: { success: false, error: "Idempotency key was already used for a different printer action." } };
  }
  return null;
};
