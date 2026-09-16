import { useQuery } from "@tanstack/react-query";
import apiClient from "@/lib/api-client";
import { ApiResponseError } from "@/lib/api/query-utils";

export function useUserDirectoryPage(offset = 0, enabled = true) {
  return useQuery({
    queryKey: ["user-directory-page", offset], enabled,
    queryFn: async () => {
      const response = await apiClient.getUsers({ limit: 100, offset });
      if (!response.success) throw new ApiResponseError("Could not load user directory", response);
      if (!Array.isArray(response.data)) throw new Error("Invalid user directory response");
      return { rows: response.data.map((row) => ({ ...row, role: row.role || undefined })), meta: response.meta };
    },
  });
}
