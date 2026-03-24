import type { ApiResponse } from "@/lib/api-client";
import type { z } from "zod";

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

export function parseWithSchema<TSchema extends z.ZodTypeAny>(
  schema: TSchema,
  payload: unknown,
  fallbackMessage: string
): z.infer<TSchema> {
  const parsed = schema.safeParse(payload);
  if (!parsed.success) {
    throw new Error(fallbackMessage);
  }
  return parsed.data;
}

export function unwrapParsedApiResponse<TSchema extends z.ZodTypeAny>(
  response: ApiResponse<unknown>,
  schema: TSchema,
  fallbackMessage: string
): z.infer<TSchema> {
  return parseWithSchema(schema, unwrapApiResponse<unknown>(response, fallbackMessage), fallbackMessage);
}
