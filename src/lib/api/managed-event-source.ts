import { getAuthenticatedStreamScope, isRequestCoordinatorScopeReady, onRequestCoordinatorScopeChange } from "@/lib/api/request-coordinator";

type EventSourceFactory = typeof EventSource;

type StreamSubscriber = {
  eventName: string;
  onMessage: (event: MessageEvent) => void;
  onError?: () => void;
  onOpen?: () => void;
};

type StreamState = {
  id: string;
  key: string;
  url: string;
  scope: string;
  source: EventSource | null;
  open: boolean;
  listening: Set<string>;
  subscribers: Map<number, StreamSubscriber>;
  reconnectTimer: number | null;
  reconnectAttempt: number;
  visibilityHandler: (() => void) | null;
  pauseWhenHidden: boolean;
};

type SubscribeOptions = {
  eventName?: string;
  onError?: () => void;
  onOpen?: () => void;
  pauseWhenHidden?: boolean;
};

const BASE_RECONNECT_MS = 2_000;
const MAX_RECONNECT_MS = 60_000;
let subscriberId = 0;
const streams = new Map<string, StreamState>();

const getEventSourceCtor = (): EventSourceFactory | null =>
  typeof EventSource === "undefined" ? null : EventSource;

const clearReconnectTimer = (state: StreamState) => {
  if (state.reconnectTimer != null) {
    window.clearTimeout(state.reconnectTimer);
    state.reconnectTimer = null;
  }
};

const closeSource = (state: StreamState) => {
  if (state.source) {
    state.source.close();
    state.source = null;
  }
  state.open = false;
  state.listening.clear();
};

const isDocumentHidden = () => typeof document !== "undefined" && document.visibilityState === "hidden";

const dispatchOpen = (state: StreamState) => {
  state.open = true;
  state.reconnectAttempt = 0;
  for (const subscriber of state.subscribers.values()) {
    subscriber.onOpen?.();
  }
};

const dispatchError = (state: StreamState) => {
  for (const subscriber of state.subscribers.values()) {
    subscriber.onError?.();
  }
};

const listen = (state: StreamState, source: EventSource, eventName: string) => {
  if (state.listening.has(eventName)) return;
  source.addEventListener(eventName, (event) => {
    if (state.source !== source || state.scope !== getAuthenticatedStreamScope()) return;
    for (const subscriber of state.subscribers.values()) {
      if (subscriber.eventName === event.type) subscriber.onMessage(event as MessageEvent);
    }
  });
  state.listening.add(eventName);
};

const connect = (state: StreamState) => {
  if (state.source || state.subscribers.size === 0) return;
  if (!isRequestCoordinatorScopeReady()) return;
  if (state.pauseWhenHidden && isDocumentHidden()) return;

  const EventSourceCtor = getEventSourceCtor();
  if (!EventSourceCtor) {
    dispatchError(state);
    return;
  }

  let source: EventSource;
  try {
    source = new EventSourceCtor(state.url, { withCredentials: true });
  } catch {
    source = new EventSourceCtor(state.url);
  }

  state.source = source;
  const eventNames = new Set(Array.from(state.subscribers.values()).map((subscriber) => subscriber.eventName));
  for (const eventName of eventNames) {
    listen(state, source, eventName);
  }

  source.onopen = () => {
    if (state.source === source && state.scope === getAuthenticatedStreamScope()) dispatchOpen(state);
  };
  source.onerror = () => {
    if (state.source !== source) return;
    closeSource(state);
    dispatchError(state);
    scheduleReconnect(state);
  };
};

const scheduleReconnect = (state: StreamState) => {
  if (state.subscribers.size === 0 || state.reconnectTimer != null) return;
  if (state.pauseWhenHidden && isDocumentHidden()) return;

  state.reconnectAttempt += 1;
  const jitter = Math.floor(Math.random() * 500);
  const delay = Math.min(MAX_RECONNECT_MS, BASE_RECONNECT_MS * 2 ** Math.min(state.reconnectAttempt - 1, 5)) + jitter;
  state.reconnectTimer = window.setTimeout(() => {
    state.reconnectTimer = null;
    connect(state);
  }, delay);
};

const ensureVisibilityHandler = (state: StreamState) => {
  if (!state.pauseWhenHidden || state.visibilityHandler || typeof document === "undefined") return;

  state.visibilityHandler = () => {
    if (!state.pauseWhenHidden) return;
    if (isDocumentHidden()) {
      clearReconnectTimer(state);
      closeSource(state);
      return;
    }
    connect(state);
  };
  document.addEventListener("visibilitychange", state.visibilityHandler);
};

const removeStream = (state: StreamState) => {
  clearReconnectTimer(state);
  closeSource(state);
  if (state.visibilityHandler && typeof document !== "undefined") {
    document.removeEventListener("visibilitychange", state.visibilityHandler);
  }
  streams.delete(state.id);
};

export const subscribeManagedEventSource = (
  key: string,
  url: string,
  onMessage: (event: MessageEvent) => void,
  options: SubscribeOptions = {}
) => {
  const eventName = options.eventName || "message";
  const scope = getAuthenticatedStreamScope();
  const streamId = JSON.stringify([key, url, scope]);
  let state = streams.get(streamId);
  if (!state) {
    state = {
      id: streamId,
      key,
      url,
      scope,
      source: null,
      open: false,
      listening: new Set(),
      subscribers: new Map(),
      reconnectTimer: null,
      reconnectAttempt: 0,
      visibilityHandler: null,
      pauseWhenHidden: options.pauseWhenHidden !== false,
    };
    streams.set(streamId, state);
  }

  const subscriptionId = ++subscriberId;
  state.subscribers.set(subscriptionId, {
    eventName,
    onMessage,
    onError: options.onError,
    onOpen: options.onOpen,
  });
  state.pauseWhenHidden = state.pauseWhenHidden && options.pauseWhenHidden !== false;

  ensureVisibilityHandler(state);
  connect(state);
  if (state.source) listen(state, state.source, eventName);
  if (state.open) options.onOpen?.();

  return () => {
    const current = streams.get(streamId);
    if (current !== state) return;
    current.subscribers.delete(subscriptionId);
    if (current.subscribers.size === 0) {
      removeStream(current);
    }
  };
};

export const closeManagedEventSources = () => {
  for (const state of Array.from(streams.values())) {
    removeStream(state);
  }
};

export const getManagedEventSourceState = () =>
  Array.from(streams.values()).map((state) => ({
    key: state.key,
    url: state.url,
    subscribers: state.subscribers.size,
    connected: Boolean(state.source),
    reconnecting: state.reconnectTimer != null,
  }));

let activeScope = getAuthenticatedStreamScope();
onRequestCoordinatorScopeChange(() => {
  const nextScope = getAuthenticatedStreamScope();
  if (nextScope === activeScope) return;
  activeScope = nextScope;
  closeManagedEventSources();
});
