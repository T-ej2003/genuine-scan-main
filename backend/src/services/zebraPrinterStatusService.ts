import net from "net";

const ZEBRA_QUERY_TIMEOUT_MS = Math.max(
  1000,
  Math.min(15_000, Number(process.env.ZEBRA_QUERY_TIMEOUT_MS || 4000) || 4000)
);
const ZEBRA_CONFIRM_POLL_MS = Math.max(
  500,
  Math.min(10_000, Number(process.env.ZEBRA_CONFIRM_POLL_MS || 1500) || 1500)
);
const ZEBRA_CONFIRM_TIMEOUT_MS = Math.max(
  5_000,
  Math.min(10 * 60_000, Number(process.env.ZEBRA_CONFIRM_TIMEOUT_MS || 60_000) || 60_000)
);

const sleep = (ms: number) => new Promise((resolve) => setTimeout(resolve, ms));

const normalizeZebraValue = (value: string) =>
  String(value || "")
    .trim()
    .replace(/^"+|"+$/g, "")
    .trim();

const queryZebraGetVar = async (params: {
  ipAddress: string;
  port: number;
  variable: string;
}) => {
  return new Promise<string>((resolve, reject) => {
    const socket = net.createConnection({
      host: params.ipAddress,
      port: params.port,
    });
    let settled = false;
    let output = "";
    let responseTimer: NodeJS.Timeout | null = null;

    const cleanup = () => {
      if (responseTimer) clearTimeout(responseTimer);
      socket.removeAllListeners();
      socket.destroy();
    };

    const finish = (fn: () => void) => {
      if (settled) return;
      settled = true;
      cleanup();
      fn();
    };

    socket.setTimeout(ZEBRA_QUERY_TIMEOUT_MS);

    socket.once("connect", () => {
      socket.write(`! U1 getvar "${params.variable}"\r\n`);
    });

    socket.on("data", (chunk) => {
      output += chunk.toString("utf8");
      if (responseTimer) clearTimeout(responseTimer);
      responseTimer = setTimeout(() => {
        finish(() => resolve(normalizeZebraValue(output)));
      }, 100);
    });

    socket.once("timeout", () => {
      finish(() => reject(new Error(`Timed out querying Zebra variable ${params.variable}`)));
    });

    socket.once("error", (error) => {
      finish(() => reject(error));
    });

    socket.once("close", () => {
      if (!settled) {
        finish(() => resolve(normalizeZebraValue(output)));
      }
    });
  });
};

export const getZebraTotalLabelCount = async (params: {
  ipAddress: string;
  port: number;
}) => {
  const raw = await queryZebraGetVar({
    ...params,
    variable: "odometer.total_label_count",
  });
  const parsed = Number.parseInt(raw.replace(/[^\d-]/g, ""), 10);
  if (!Number.isFinite(parsed)) {
    throw new Error(`Unexpected Zebra odometer response: ${raw || "empty"}`);
  }
  return parsed;
};

export const waitForZebraLabelConfirmation = async (params: {
  ipAddress: string;
  port: number;
  startingLabelCount: number;
  expectedIncrement?: number;
  timeoutMs?: number;
}) => {
  const expectedIncrement = Math.max(1, Number(params.expectedIncrement || 1) || 1);
  const deadline = Date.now() + (params.timeoutMs || ZEBRA_CONFIRM_TIMEOUT_MS);
  let lastCount = params.startingLabelCount;

  while (Date.now() < deadline) {
    lastCount = await getZebraTotalLabelCount({
      ipAddress: params.ipAddress,
      port: params.port,
    });
    if (lastCount >= params.startingLabelCount + expectedIncrement) {
      return {
        confirmed: true as const,
        lastCount,
      };
    }
    await sleep(ZEBRA_CONFIRM_POLL_MS);
  }

  throw new Error(
    `Zebra confirmation timed out after ${params.timeoutMs || ZEBRA_CONFIRM_TIMEOUT_MS}ms (label count ${lastCount}, expected at least ${
      params.startingLabelCount + expectedIncrement
    }).`
  );
};
