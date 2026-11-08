// HTTP entrypoint contract: UUID versions 1-5.
const REQUEST_ID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;

export const isValidRequestId = (value: unknown): value is string =>
  typeof value === "string" && REQUEST_ID.test(value);
