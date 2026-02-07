export type MutationEventDetail = {
  endpoint: string;
  method: string;
};

const EVENT_NAME = "data:mutated";

export const emitMutationEvent = (detail: MutationEventDetail) => {
  if (typeof window === "undefined") return;
  try {
    window.dispatchEvent(new CustomEvent(EVENT_NAME, { detail }));
  } catch {
    // ignore
  }
};

export const onMutationEvent = (cb: (detail: MutationEventDetail) => void) => {
  if (typeof window === "undefined") return () => {};
  const handler = (e: Event) => {
    const evt = e as CustomEvent<MutationEventDetail>;
    if (evt?.detail) cb(evt.detail);
  };
  window.addEventListener(EVENT_NAME, handler);
  return () => window.removeEventListener(EVENT_NAME, handler);
};
