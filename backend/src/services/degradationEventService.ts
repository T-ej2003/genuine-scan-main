import { VerificationDegradationMode } from "@prisma/client";

import prisma from "../config/database";

const getStore = () => (prisma as any).degradationEvent;

export const recordDegradationEvent = async (input: {
  dependencyKey: string;
  mode: VerificationDegradationMode;
  code: string;
  message: string;
  context?: Record<string, unknown> | null;
}) => {
  const store = getStore();
  if (!store?.create) return null;

  try {
    return await store.create({
      data: {
        dependencyKey: input.dependencyKey,
        mode: input.mode,
        code: input.code,
        message: input.message,
        context: input.context ?? undefined,
      },
    });
  } catch (error) {
    console.warn("degradation event skipped:", error);
    return null;
  }
};
