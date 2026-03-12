const normalize = (value?: string | null) => String(value || "").trim();

const hasAny = (value: string, patterns: string[]) => patterns.some((pattern) => value.includes(pattern));

export const sanitizePrinterActionError = (
  raw?: string | null,
  fallback = "Printing is unavailable right now."
) => {
  const original = normalize(raw);
  if (!original) return fallback;

  const value = original.toLowerCase();

  if (
    hasAny(value, [
      "unique constraint failed",
      "duplicate key",
      "already exists for this endpoint",
      "already exists for this printer uri",
      "p2002",
    ])
  ) {
    return "A saved printer profile already uses this connection. Open the existing setup to edit it or remove it first.";
  }
  if (hasAny(value, ["busy", "conflict", "please retry"])) {
    return "Another printing action is already using this batch. Please wait a moment and try again.";
  }
  if (hasAny(value, ["127.0.0.1", "localhost", "local print agent", "workstation agent"])) {
    return "The workstation connector is not available on this device right now.";
  }
  if (hasAny(value, ["heartbeat", "trust", "attestation", "signature", "fingerprint", "certificate", "mtls"])) {
    return "The secure printer connection is not ready yet. Refresh and try again in a moment.";
  }
  if (hasAny(value, ["gateway", "private-lan"]) && hasAny(value, ["offline", "credentials", "missing"])) {
    return "The site print connector needs attention before this printer can be used.";
  }
  if (hasAny(value, ["application/pdf", "pdf is not advertised", "format unsupported"])) {
    return "This office printer does not support the required MSCQR print format.";
  }
  if (hasAny(value, ["ipp", "ipps"]) && hasAny(value, ["unreachable", "validation failed", "not reachable"])) {
    return "The saved office printer could not be reached. Check the printer setup and try again.";
  }
  if (hasAny(value, ["tcp", "socket", "host and port", "9100", "jetdirect", "network-direct"])) {
    return "The saved factory printer could not be reached. Check the printer or network connection and try again.";
  }
  if (hasAny(value, ["command language", "zpl", "tspl", "epl", "cpcl", "sbpl", "esc/pos", "esc_pos"])) {
    return "This printer profile needs a compatible setup before it can be used.";
  }
  if (hasAny(value, ["token", "payload", "print item", "issued", "agent_acked", "print session"])) {
    return "This print session changed while printing. Start a fresh print job and try again.";
  }

  return fallback;
};
