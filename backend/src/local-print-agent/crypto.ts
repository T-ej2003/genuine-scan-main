import { randomBytes } from "crypto";

export const randomOpaqueToken = (bytes = 32) => randomBytes(bytes).toString("base64url");
