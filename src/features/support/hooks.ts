import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";

import apiClient from "@/lib/api-client";
import { parseWithSchema, unwrapApiResponse, unwrapParsedApiResponse } from "@/lib/api/query-utils";
import { emitMutationEvent } from "@/lib/mutation-events";
import { queryKeys } from "@/lib/query-keys";

import {
  supportAssigneeArraySchema,
  supportIssueReportArraySchema,
  supportIssueReportListResponseSchema,
  supportTicketArraySchema,
  supportTicketDetailSchema,
  supportTicketListResponseSchema,
} from "../../../shared/contracts/runtime/support.ts";

import type {
  SupportAssignee,
  SupportIssueReport,
  SupportQueueFilters,
  SupportTicket,
  SupportTicketPriority,
  SupportTicketStatus,
  SupportTicketDetail,
} from "@/features/support/types";

type SupportTicketListResponse = {
  tickets: SupportTicket[];
  total: number;
};

type SupportIssueReportListResponse = {
  reports: SupportIssueReport[];
  total: number;
};

const supportQueryOptions = (filters: SupportQueueFilters) => ({
  status: filters.status !== "all" ? (filters.status as SupportTicketStatus) : undefined,
  priority: filters.priority !== "all" ? (filters.priority as SupportTicketPriority) : undefined,
  search: filters.search.trim() || undefined,
  limit: 120,
});

export function useSupportTickets(filters: SupportQueueFilters) {
  return useQuery({
    queryKey: queryKeys.support.tickets(filters),
    queryFn: async (): Promise<SupportTicketListResponse> => {
      const payload = unwrapApiResponse<unknown>(
        await apiClient.getSupportTickets(supportQueryOptions(filters)),
        "Could not load support tickets."
      );

      if (Array.isArray(payload)) {
        const tickets = parseWithSchema(supportTicketArraySchema, payload, "Could not load support tickets.");
        return {
          tickets,
          total: tickets.length,
        };
      }

      return parseWithSchema(
        supportTicketListResponseSchema,
        {
          tickets: Array.isArray((payload as { tickets?: unknown[] })?.tickets) ? (payload as { tickets: unknown[] }).tickets : [],
          total: Number((payload as { total?: unknown }).total || (Array.isArray((payload as { tickets?: unknown[] })?.tickets) ? (payload as { tickets: unknown[] }).tickets.length : 0)),
        },
        "Could not load support tickets."
      );
    },
  });
}

export function useSupportIssueReports() {
  return useQuery({
    queryKey: queryKeys.support.reports(),
    queryFn: async (): Promise<SupportIssueReportListResponse> => {
      const payload = unwrapApiResponse<unknown>(
        await apiClient.getSupportIssueReports({ limit: 60 }),
        "Could not load support issue reports."
      );

      if (Array.isArray(payload)) {
        const reports = parseWithSchema(supportIssueReportArraySchema, payload, "Could not load support issue reports.");
        return {
          reports,
          total: reports.length,
        };
      }

      return parseWithSchema(
        supportIssueReportListResponseSchema,
        {
          reports: Array.isArray((payload as { reports?: unknown[] })?.reports) ? (payload as { reports: unknown[] }).reports : [],
          total: Number((payload as { total?: unknown }).total || (Array.isArray((payload as { reports?: unknown[] })?.reports) ? (payload as { reports: unknown[] }).reports.length : 0)),
        },
        "Could not load support issue reports."
      );
    },
  });
}

export function useSupportTicketDetail(ticketId?: string) {
  return useQuery({
    queryKey: queryKeys.support.ticketDetail(ticketId),
    enabled: Boolean(ticketId),
    queryFn: async (): Promise<SupportTicketDetail> =>
      unwrapParsedApiResponse(
        await apiClient.getSupportTicket(String(ticketId)),
        supportTicketDetailSchema,
        "Could not load support ticket detail."
      ),
  });
}

export function useSupportAssignableUsers(enabled: boolean) {
  return useQuery({
    queryKey: queryKeys.support.assignees(),
    enabled,
    queryFn: async (): Promise<SupportAssignee[]> => {
      const rows = unwrapApiResponse<unknown>(await apiClient.getUsers(), "Could not load support assignees.");
      if (!Array.isArray(rows)) return [];
      return parseWithSchema(
        supportAssigneeArraySchema,
        rows.filter(
          (row) =>
            !!row &&
            typeof row === "object" &&
            ["LICENSEE_ADMIN", "SUPER_ADMIN", "ORG_ADMIN"].includes(String((row as SupportAssignee).role || ""))
        ),
        "Could not load support assignees."
      );
    },
  });
}

const invalidateSupportQueries = async (queryClient: ReturnType<typeof useQueryClient>) => {
  await Promise.all([
    queryClient.invalidateQueries({ queryKey: queryKeys.support.tickets() }),
    queryClient.invalidateQueries({ queryKey: queryKeys.support.reports() }),
    queryClient.invalidateQueries({ queryKey: queryKeys.support.ticketDetail() }),
  ]);
};

export function useUpdateSupportTicketMutation() {
  const queryClient = useQueryClient();

  return useMutation({
    mutationFn: async (params: {
      ticketId: string;
      status: SupportTicketStatus;
      assignedToUserId: string | null;
    }) => {
      const response = await apiClient.patchSupportTicket(params.ticketId, {
        status: params.status,
        assignedToUserId: params.assignedToUserId,
      });

      if (!response.success) throw new Error(response.error || "Could not update support ticket.");
      return response.data;
    },
    onSuccess: async () => {
      emitMutationEvent({ endpoint: "/support/tickets", method: "PATCH" });
      await invalidateSupportQueries(queryClient);
    },
  });
}

export function useAddSupportTicketMessageMutation() {
  const queryClient = useQueryClient();

  return useMutation({
    mutationFn: async (params: {
      ticketId: string;
      message: string;
      isInternal: boolean;
    }) => {
      const response = await apiClient.addSupportTicketMessage(params.ticketId, {
        message: params.message,
        isInternal: params.isInternal,
      });

      if (!response.success) throw new Error(response.error || "Could not add support message.");
      return response.data;
    },
    onSuccess: async () => {
      emitMutationEvent({ endpoint: "/support/tickets/messages", method: "POST" });
      await invalidateSupportQueries(queryClient);
    },
  });
}

export function useRespondToIssueReportMutation() {
  const queryClient = useQueryClient();

  return useMutation({
    mutationFn: async (params: { reportId: string; message: string }) => {
      const response = await apiClient.respondToSupportIssueReport(params.reportId, {
        message: params.message,
        status: "RESPONDED",
      });

      if (!response.success) throw new Error(response.error || "Could not send support response.");
      return response.data;
    },
    onSuccess: async () => {
      emitMutationEvent({ endpoint: "/support/reports/respond", method: "POST" });
      await invalidateSupportQueries(queryClient);
    },
  });
}
