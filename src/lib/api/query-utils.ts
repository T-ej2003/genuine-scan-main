import type { ApiResponse } from "@/lib/api-client";

export function unwrapApiResponse<T>(response: ApiResponse<unknown>, fallbackMessage: string): T {
  if (!response.success) {
    throw new Error(response.error || fallbackMessage);
  }

  return response.data as T;
}

export function unwrapArrayResponse<T>(response: ApiResponse<unknown>, fallbackMessage: string): T[] {
  const payload = unwrapApiResponse<unknown>(response, fallbackMessage);
  return Array.isArray(payload) ? (payload as T[]) : [];
}
