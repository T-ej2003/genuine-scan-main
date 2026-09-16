import React from "react";
import { act, cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { afterEach, expect, it, vi } from "vitest";
import { MemoryRouter } from "react-router";
import AuditLogs from "@/pages/AuditLogs";
import apiClient from "@/lib/api-client";

vi.mock("@/contexts/AuthContext", () => ({ useAuth: () => ({ user: { id: "admin", role: "super_admin" } }) }));
vi.mock("@/components/layout/DashboardLayout", () => ({ DashboardLayout: ({ children }: any) => <div>{children}</div> }));
vi.mock("@/hooks/use-toast", () => ({ useToast: () => ({ toast: vi.fn() }) }));
vi.mock("@/lib/mutation-events", () => ({ onMutationEvent: () => () => undefined }));
vi.mock("@/components/ui/select", () => ({
  Select: ({ value, onValueChange, children }: any) => <select value={value} onChange={e => onValueChange(e.target.value)}>{children}</select>,
  SelectTrigger: () => null, SelectValue: () => null,
  SelectContent: ({ children }: any) => <>{children}</>,
  SelectItem: ({ value, children }: any) => <option value={value}>{children}</option>,
}));
vi.mock("@/lib/api-client", () => ({ default: {
  getAuditLogs: vi.fn(), getFraudReports: vi.fn(), getLicensees: vi.fn(),
  streamAuditLogs: vi.fn(), listPrintJobs: vi.fn(),
} }));
afterEach(() => { cleanup(); vi.clearAllMocks(); });

it("suppresses unscoped REST/SSE and rejects old or foreign brand events", async () => {
  const subscriptions: Array<{ receive: (log: any) => void; stop: ReturnType<typeof vi.fn>; scope?: string }> = [];
  vi.mocked(apiClient.getLicensees).mockResolvedValue({ success: true, data: [{ id: "A", name: "Brand A" }, { id: "B", name: "Brand B" }] } as any);
  vi.mocked(apiClient.getFraudReports).mockResolvedValue({ success: true, data: [] } as any);
  vi.mocked(apiClient.getAuditLogs).mockResolvedValue({ success: true, data: [] });
  vi.mocked(apiClient.streamAuditLogs).mockImplementation((receive, _error, scope) => {
    const stop = vi.fn(); subscriptions.push({ receive, stop, scope }); return stop;
  });
  render(<MemoryRouter><AuditLogs /></MemoryRouter>);
  await screen.findByText("Brand A");
  expect(apiClient.getAuditLogs).not.toHaveBeenCalled();
  expect(subscriptions).toHaveLength(0);
  const select = screen.getAllByRole("combobox").find(el => el.textContent?.includes("Brand A"))!;
  fireEvent.change(select, { target: { value: "A" } });
  await waitFor(() => expect(subscriptions).toHaveLength(1));
  expect(subscriptions[0].scope).toBe("A");
  expect(apiClient.getAuditLogs).toHaveBeenLastCalledWith(expect.objectContaining({ licenseeId: "A" }));
  const event = (licenseeId: string, name: string) => ({ id: name, licenseeId, action: "LOGIN_SUCCESS", createdAt: new Date().toISOString(), user: { name, email: "fixture@example.test" } });
  act(() => { subscriptions[0].receive(event("A", "Actor-A")); subscriptions[0].receive(event("B", "Foreign-B")); });
  expect(screen.getAllByText(/Actor-A/).length).toBeGreaterThan(0);
  expect(screen.queryByText(/Foreign-B/)).toBeNull();
  fireEvent.change(select, { target: { value: "B" } });
  await waitFor(() => expect(subscriptions).toHaveLength(2));
  expect(subscriptions[0].stop).toHaveBeenCalledOnce();
  act(() => subscriptions[0].receive(event("A", "Late-A")));
  expect(screen.queryByText(/Actor-A|Late-A/)).toBeNull();
  expect(subscriptions[1].scope).toBe("B");
  act(() => subscriptions[1].receive(event("B", "Actor-B")));
  expect(screen.getAllByText(/Actor-B/).length).toBeGreaterThan(0);
  fireEvent.change(select, { target: { value: "all" } });
  expect(subscriptions[1].stop).toHaveBeenCalledOnce();
  act(() => subscriptions[1].receive(event("B", "Late-B")));
  expect(screen.queryByText(/Actor-B|Late-B/)).toBeNull();
  expect(subscriptions).toHaveLength(2);
});
