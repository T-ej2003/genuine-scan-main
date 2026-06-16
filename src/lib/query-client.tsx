import { useEffect } from "react";
import { QueryClient, useQueryClient } from "@tanstack/react-query";

import { ApiResponseError } from "@/lib/api/query-utils";
import { isActivePrintSessionSuppressed } from "@/lib/active-print-session";
import { onMutationEvent } from "@/lib/mutation-events";
import { queryKeys } from "@/lib/query-keys";

export const queryClient = new QueryClient({
  defaultOptions: {
    queries: {
      retry: (failureCount, error) => {
        if (error instanceof ApiResponseError) {
          if (error.code === "RATE_LIMITED") return false;
          if ([400, 401, 403, 404, 409, 428, 429].includes(Number(error.status || 0))) return false;
        }
        return failureCount < 1;
      },
      staleTime: 10_000,
      refetchOnWindowFocus: false,
    },
    mutations: {
      retry: 0,
    },
  },
});

export function MutationEventBridge(): null {
  const client = useQueryClient();

  useEffect(() => {
    return onMutationEvent((detail) => {
      const endpoint = detail.endpoint || "";

      if (isActivePrintSessionSuppressed()) {
        return;
      }

      if (endpoint.startsWith("/notifications")) {
        void client.invalidateQueries({ queryKey: queryKeys.layout.notifications() });
        void client.invalidateQueries({ queryKey: queryKeys.layout.attentionQueue() });
        return;
      }

      if (endpoint.startsWith("/qr") || endpoint.includes("/print") || endpoint.includes("/batches")) {
        void client.invalidateQueries({ queryKey: ["dashboard"] });
        void client.invalidateQueries({ queryKey: ["batches"] });
        void client.invalidateQueries({ queryKey: ["printing"] });
        return;
      }

      if (endpoint.startsWith("/licensees") || endpoint.startsWith("/users") || endpoint.includes("/manufacturers")) {
        void client.invalidateQueries({ queryKey: ["dashboard"] });
        void client.invalidateQueries({ queryKey: ["manufacturers"] });
        return;
      }

      void client.invalidateQueries({ refetchType: "active" });
    });
  }, [client]);

  return null;
}
