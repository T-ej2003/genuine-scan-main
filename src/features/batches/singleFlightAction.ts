import type { MutableRefObject } from "react";

export const runSingleFlightAction = (
  inFlightRef: MutableRefObject<Map<string, Promise<void>>>,
  key: string,
  action: () => Promise<void>,
) => {
  const current = inFlightRef.current.get(key);
  if (current) return current;
  const run = action().finally(() => {
    inFlightRef.current.delete(key);
  });
  inFlightRef.current.set(key, run);
  return run;
};
