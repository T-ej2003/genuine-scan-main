export const HELP_ASSISTANT_OPEN_EVENT = "mscqr:help-assistant-open";

export type HelpAssistantOpenPayload = {
  query?: string;
  entryId?: string;
};

export const openHelpAssistant = (payload: HelpAssistantOpenPayload = {}) => {
  if (typeof window === "undefined") return;
  window.dispatchEvent(new CustomEvent<HelpAssistantOpenPayload>(HELP_ASSISTANT_OPEN_EVENT, { detail: payload }));
};
