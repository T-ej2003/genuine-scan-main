import { useEffect } from "react";
import { QueryClient, useQueryClient } from "@tanstack/react-query";

import { onMutationEvent } from "@/lib/mutation-events";

export const queryClient = new QueryClient({
  defaultOptions: {
    queries: {
      retry: 1,
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
    return onMutationEvent(() => {
      void client.invalidateQueries();
    });
  }, [client]);

  return null;
}
