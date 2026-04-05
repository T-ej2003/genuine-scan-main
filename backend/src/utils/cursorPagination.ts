type DateCursorShape = {
  createdAt: string;
  id: string;
};

export const encodeDateCursor = (row: { createdAt: Date | string; id: string }) => {
  const payload: DateCursorShape = {
    createdAt: row.createdAt instanceof Date ? row.createdAt.toISOString() : String(row.createdAt),
    id: String(row.id),
  };
  return Buffer.from(JSON.stringify(payload), "utf8").toString("base64url");
};

export const decodeDateCursor = (raw: unknown): DateCursorShape | null => {
  const value = String(raw || "").trim();
  if (!value) return null;

  try {
    const parsed = JSON.parse(Buffer.from(value, "base64url").toString("utf8")) as DateCursorShape;
    if (!parsed?.createdAt || !parsed?.id) return null;
    const createdAt = new Date(parsed.createdAt);
    if (!Number.isFinite(createdAt.getTime())) return null;
    return {
      createdAt: createdAt.toISOString(),
      id: String(parsed.id),
    };
  } catch {
    return null;
  }
};

export const buildDateCursorWhere = (params: {
  createdAtField?: string;
  idField?: string;
  cursor?: string | null;
}) => {
  const parsed = decodeDateCursor(params.cursor);
  if (!parsed) return null;

  const createdAtField = params.createdAtField || "createdAt";
  const idField = params.idField || "id";

  return {
    OR: [
      {
        [createdAtField]: {
          lt: new Date(parsed.createdAt),
        },
      },
      {
        [createdAtField]: new Date(parsed.createdAt),
        [idField]: {
          lt: parsed.id,
        },
      },
    ],
  } as Record<string, unknown>;
};
