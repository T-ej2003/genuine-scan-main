type EventSourceFactory = typeof EventSource;

type StreamSubscriber = {
  eventName: string;
  onMessage: (event: MessageEvent) => void;
  onError?: () => void;
  onOpen?: () => void;
};

type StreamState = {
  key: string;
  url: string;
  source: EventSource | null;
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
};

const isDocumentHidden = () => typeof document !== "undefined" && document.visibilityState === "hidden";

const dispatchOpen = (state: StreamState) => {
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

const connect = (state: StreamState) => {
  if (state.source || state.subscribers.size === 0) return;
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
  const dispatchMessage = (event: MessageEvent) => {
    for (const subscriber of state.subscribers.values()) {
      if (subscriber.eventName === event.type) {
        subscriber.onMessage(event);
      }
    }
  };

  const eventNames = new Set(Array.from(state.subscribers.values()).map((subscriber) => subscriber.eventName));
  for (const eventName of eventNames) {
    source.addEventListener(eventName, dispatchMessage as EventListener);
  }

  source.onopen = () => dispatchOpen(state);
  source.onerror = () => {
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
  streams.delete(state.key);
};

export const subscribeManagedEventSource = (
  key: string,
  url: string,
  onMessage: (event: MessageEvent) => void,
  options: SubscribeOptions = {}
) => {
  const eventName = options.eventName || "message";
  let state = streams.get(key);
  if (!state) {
    state = {
      key,
      url,
      source: null,
      subscribers: new Map(),
      reconnectTimer: null,
      reconnectAttempt: 0,
      visibilityHandler: null,
      pauseWhenHidden: options.pauseWhenHidden !== false,
    };
    streams.set(key, state);
  }

  const id = ++subscriberId;
  state.subscribers.set(id, {
    eventName,
    onMessage,
    onError: options.onError,
    onOpen: options.onOpen,
  });
  state.pauseWhenHidden = state.pauseWhenHidden && options.pauseWhenHidden !== false;

  ensureVisibilityHandler(state);
  connect(state);

  return () => {
    const current = streams.get(key);
    if (!current) return;
    current.subscribers.delete(id);
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

if (typeof window !== "undefined") {
  window.addEventListener("auth:logout", closeManagedEventSources);
}
