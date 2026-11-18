import React from "react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { act, cleanup, renderHook, waitFor } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import apiClient from "@/lib/api-client";
import { useDashboardNotificationCenter } from "@/features/layout/hooks";
import { setRequestCoordinatorScope } from "@/lib/api/request-coordinator";

const refresh = vi.fn();
vi.mock("@/contexts/AuthContext", () => ({ useAuth: () => ({ refresh }) }));
vi.mock("@/lib/api-client", () => ({ default: {
  getNotifications: vi.fn(),
  streamNotifications: vi.fn(),
} }));

describe("notification SSE recovery and scope", () => {
  let onEvent: ((event: unknown) => void) | undefined;
  let onError: (() => void) | undefined;
  let onOpen: (() => void) | undefined;
  let client: QueryClient;
  const wrapper = ({ children }: { children: React.ReactNode }) => <QueryClientProvider client={client}>{children}</QueryClientProvider>;

  beforeEach(() => {
    client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
    vi.mocked(apiClient.getNotifications).mockResolvedValue({ success: true, data: { notifications: [], unread: 0 } } as never);
    vi.mocked(apiClient.streamNotifications).mockImplementation((message, error, open) => {
      onEvent = message as (event: unknown) => void;
      onError = error;
      onOpen = open;
      return () => undefined;
    });
    setRequestCoordinatorScope({ id: "actor-a" });
  });

  afterEach(() => {
    vi.useRealTimers();
    cleanup();
    client.clear();
    setRequestCoordinatorScope(null);
    vi.clearAllMocks();
  });

  it("retains the last verified snapshot through a 503 and resynchronizes on recovery", async () => {
    const { result } = renderHook(() => useDashboardNotificationCenter("actor-a"), { wrapper });
    await waitFor(() => expect(result.current.notificationsLoading).toBe(false));
    expect(apiClient.getNotifications).toHaveBeenCalledOnce();
    act(() => {
      onOpen?.();
      onEvent?.({ kind: "snapshot", notifications: [{ id: "first", title: "First" }], unread: 1 });
    });
    expect(result.current.notifications.map((row) => row.id)).toEqual(["first"]);
    expect(result.current.unreadNotifications).toBe(1);
    expect(apiClient.getNotifications).toHaveBeenCalledTimes(1);

    vi.mocked(apiClient.getNotifications).mockResolvedValueOnce({ success: false, status: 503 } as never);
    await act(async () => { onError?.(); await result.current.loadNotifications({ force: true }); });
    expect(result.current.notifications.map((row) => row.id)).toEqual(["first"]);
    expect(result.current.notificationsLive).toBe(false);

    act(() => {
      onOpen?.();
      onEvent?.({ kind: "snapshot", notifications: [{ id: "second", title: "Second" }], unread: 2, serverTime: "2026-11-18T20:08:00.000Z" });
      onEvent?.({ kind: "snapshot", notifications: [{ id: "second", title: "Second" }], unread: 2, serverTime: "2026-11-18T20:08:00.000Z" });
      onEvent?.({ kind: "snapshot", notifications: [{ id: "stale" }], unread: 0, serverTime: "2026-11-18T20:07:00.000Z" });
    });
    expect(result.current.notifications.map((row) => row.id)).toEqual(["second"]);
    expect(result.current.unreadNotifications).toBe(2);
    expect(result.current.notificationsLive).toBe(true);
  });

  it("ignores a late HTTP snapshot when a newer stream snapshot has arrived", async () => {
    const { result } = renderHook(() => useDashboardNotificationCenter("actor-a"), { wrapper });
    await waitFor(() => expect(result.current.notificationsLoading).toBe(false));
    let resolveRead: (value: unknown) => void = () => undefined;
    vi.mocked(apiClient.getNotifications).mockImplementationOnce(() => new Promise((resolve) => { resolveRead = resolve; }) as never);
    let pending: Promise<void> | undefined;
    act(() => { pending = result.current.loadNotifications({ force: true }); });
    await waitFor(() => expect(apiClient.getNotifications).toHaveBeenCalledTimes(2));
    act(() => onEvent?.({ kind: "snapshot", notifications: [{ id: "new" }], unread: 1 }));
    await act(async () => {
      resolveRead({ success: true, data: { notifications: [{ id: "old" }], unread: 0 } });
      await pending;
    });
    expect(result.current.notifications.map((row) => row.id)).toEqual(["new"]);
    expect(result.current.unreadNotifications).toBe(1);
  });

  it("discards old-scope events and requests authentication recovery on expiry", async () => {
    const { result } = renderHook(() => useDashboardNotificationCenter("actor-a"), { wrapper });
    await waitFor(() => expect(result.current.notificationsLoading).toBe(false));
    expect(apiClient.streamNotifications).toHaveBeenCalledOnce();
    const oldEvent = onEvent;
    act(() => oldEvent?.({ kind: "snapshot", notifications: [{ id: "private" }], unread: 1 }));
    expect(result.current.unreadNotifications).toBe(1);

    act(() => setRequestCoordinatorScope({ id: "actor-b" }));
    expect(result.current.notifications).toEqual([]);
    act(() => oldEvent?.({ kind: "snapshot", notifications: [{ id: "leaked" }], unread: 1 }));
    expect(result.current.notifications).toEqual([]);
    act(() => onEvent?.({ kind: "auth_expired" }));
    expect(refresh).toHaveBeenCalledOnce();
  });

  it("uses a sparse authoritative read if a connected stream silently stops delivering snapshots", async () => {
    vi.useFakeTimers();
    const { result } = renderHook(() => useDashboardNotificationCenter("actor-a"), { wrapper });
    await act(async () => { await Promise.resolve(); await Promise.resolve(); });
    expect(apiClient.getNotifications).toHaveBeenCalledOnce();
    act(() => {
      onOpen?.();
      onEvent?.({ kind: "snapshot", notifications: [], unread: 0 });
    });
    await act(async () => { await vi.advanceTimersByTimeAsync(9 * 60_000); });
    expect(apiClient.getNotifications).toHaveBeenCalledOnce();
    await act(async () => { await vi.advanceTimersByTimeAsync(3 * 60_000); });
    expect(apiClient.getNotifications).toHaveBeenCalledTimes(2);
    expect(result.current.notificationsLive).toBe(true);
  });
});
