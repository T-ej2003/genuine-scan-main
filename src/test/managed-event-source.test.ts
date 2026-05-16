import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import {
  closeManagedEventSources,
  getManagedEventSourceState,
  subscribeManagedEventSource,
} from "@/lib/api/managed-event-source";

class MockEventSource {
  static instances: MockEventSource[] = [];
  url: string;
  closed = false;
  onerror: (() => void) | null = null;
  onopen: (() => void) | null = null;
  listeners = new Map<string, Array<(event: MessageEvent) => void>>();

  constructor(url: string) {
    this.url = url;
    MockEventSource.instances.push(this);
  }

  addEventListener(type: string, listener: (event: MessageEvent) => void) {
    const listeners = this.listeners.get(type) || [];
    listeners.push(listener);
    this.listeners.set(type, listeners);
  }

  close() {
    this.closed = true;
  }

  emit(type: string, data: unknown) {
    const event = { type, data: JSON.stringify(data) } as MessageEvent;
    for (const listener of this.listeners.get(type) || []) {
      listener(event);
    }
  }
}

describe("managed EventSource", () => {
  beforeEach(() => {
    vi.useFakeTimers();
    vi.spyOn(Math, "random").mockReturnValue(0);
    MockEventSource.instances = [];
    Object.defineProperty(globalThis, "EventSource", {
      configurable: true,
      writable: true,
      value: MockEventSource,
    });
  });

  afterEach(() => {
    closeManagedEventSources();
    vi.useRealTimers();
    vi.restoreAllMocks();
  });

  it("dedupes identical stream connections until the final subscriber closes", () => {
    const firstMessage = vi.fn();
    const secondMessage = vi.fn();

    const stopFirst = subscribeManagedEventSource("dashboard:events", "/api/events/dashboard", firstMessage, {
      eventName: "realtime",
    });
    const stopSecond = subscribeManagedEventSource("dashboard:events", "/api/events/dashboard", secondMessage, {
      eventName: "realtime",
    });

    expect(MockEventSource.instances).toHaveLength(1);
    MockEventSource.instances[0].emit("realtime", { channel: "dashboard" });
    expect(firstMessage).toHaveBeenCalledTimes(1);
    expect(secondMessage).toHaveBeenCalledTimes(1);

    stopFirst();
    expect(MockEventSource.instances[0].closed).toBe(false);
    stopSecond();
    expect(MockEventSource.instances[0].closed).toBe(true);
    expect(getManagedEventSourceState()).toEqual([]);
  });

  it("closes native EventSource on error and reconnects with controlled backoff", () => {
    const onError = vi.fn();

    subscribeManagedEventSource("notifications:events", "/api/events/notifications?limit=24", vi.fn(), {
      eventName: "realtime",
      onError,
    });

    expect(MockEventSource.instances).toHaveLength(1);
    MockEventSource.instances[0].onerror?.();

    expect(MockEventSource.instances[0].closed).toBe(true);
    expect(onError).toHaveBeenCalledTimes(1);
    expect(getManagedEventSourceState()[0].reconnecting).toBe(true);

    vi.advanceTimersByTime(2_000);

    expect(MockEventSource.instances).toHaveLength(2);
    expect(MockEventSource.instances[1].url).toBe("/api/events/notifications?limit=24");
  });
});
