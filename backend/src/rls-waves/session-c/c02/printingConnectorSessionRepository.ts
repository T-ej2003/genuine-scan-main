import { Prisma } from "@prisma/client";

import prisma from "../../../config/database";

type ConnectorSessionMutationResult = {
  state: "CONNECTED" | "DISCONNECTED";
  lastMessageSeq?: number;
  attestationRenewed?: boolean;
};

export const mutatePrintingConnectorSession = async (input: {
  operation: "OPEN" | "ADVANCE" | "CHECK" | "CLOSE";
  sessionId: string;
  registrationId: string;
  payload: Record<string, unknown>;
}): Promise<ConnectorSessionMutationResult> => {
  const rows = await prisma.$queryRaw<Array<{ result: ConnectorSessionMutationResult }>>(Prisma.sql`
    SELECT app_rls.printing_connector_session(
      ${input.operation}::text,${input.sessionId}::text,${input.registrationId}::text,
      ${input.payload}::jsonb
    ) AS result
  `);
  if (rows.length !== 1 || !rows[0].result
      || !["CONNECTED", "DISCONNECTED"].includes(rows[0].result.state)) {
    throw new Error("PRINTING_BOUNDARY_INVALID_RESULT");
  }
  return rows[0].result;
};
