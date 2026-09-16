import React from "react";
import { cleanup, renderHook, waitFor } from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { afterEach, expect, it, vi } from "vitest";
import apiClient from "@/lib/api-client";
import { useUserDirectoryPage } from "@/hooks/useUserDirectoryPage";
import { useSupportAssignableUsers } from "@/features/support/hooks";

vi.mock("@/lib/api-client", () => ({ default: { getUsers: vi.fn() } }));
afterEach(() => { cleanup(); vi.clearAllMocks(); });

it("keeps user pagination through incident and support consumers without widening assignee roles", async () => {
  vi.mocked(apiClient.getUsers).mockImplementation(async (options) => ({ success: true,
    data: [{ id: `user-${options?.offset}`, role: "SUPER_ADMIN", name: "Fixture admin", email: "admin@example.test" },
      { id: "excluded-maker", role: "MANUFACTURER_ADMIN", name: "Fixture maker", email: "maker@example.test" }],
    meta: { total: 102, limit: 100, offset: options?.offset || 0 },
  }));
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  const wrapper = ({ children }: { children: React.ReactNode }) => <QueryClientProvider client={client}>{children}</QueryClientProvider>;
  const { result, rerender } = renderHook(({ offset }) => ({
    directory: useUserDirectoryPage(offset), support: useSupportAssignableUsers(true, offset),
  }), { wrapper, initialProps: { offset: 0 } });
  await waitFor(() => expect(result.current.support.data?.rows).toHaveLength(1));
  expect(result.current.directory.data?.rows).toHaveLength(2);
  rerender({ offset: 100 });
  await waitFor(() => expect(result.current.support.data?.rows[0]?.id).toBe("user-100"));
  expect(result.current.support.data?.meta).toEqual({ total: 102, limit: 100, offset: 100 });
  expect(result.current.directory.data?.meta).toEqual({ total: 102, limit: 100, offset: 100 });
  expect(apiClient.getUsers).toHaveBeenLastCalledWith({ limit: 100, offset: 100 });
});
