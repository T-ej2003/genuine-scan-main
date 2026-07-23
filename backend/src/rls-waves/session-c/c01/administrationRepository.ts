import { Prisma } from "@prisma/client";

import { getB01AuthenticatedPrisma } from "../../session-b/b01/runtimeClients";

export const administrationPurposes = {
  createLicensee: "administration-create-licensee",
  updateLicensee: "administration-update-licensee",
  deleteLicensee: "administration-delete-licensee",
  createUser: "administration-create-user",
  updateUser: "administration-update-user",
  deleteUser: "administration-delete-user",
  restoreManufacturer: "administration-restore-manufacturer",
} as const;

export type AdministrationPurpose = (typeof administrationPurposes)[keyof typeof administrationPurposes];

export class AdministrationAccessError extends Error {
  constructor(message: string, readonly statusCode = 403) {
    super(message);
    this.name = "AdministrationAccessError";
  }
}

type JsonResultRow = { result: Prisma.JsonValue };

const required = (value: unknown, label: string) => {
  const normalized = String(value || "").trim();
  if (!normalized) throw new AdministrationAccessError(`Administration requires ${label}`, 401);
  return normalized;
};

const call = async <T>(
  functionName: AdministrationPurpose,
  capability: string,
  requestId: string,
  input: Record<string, unknown>
) => {
  const payload = JSON.stringify(input);
  const purpose = functionName;
  const client = getB01AuthenticatedPrisma();
  const rows = functionName === administrationPurposes.createLicensee
    ? await client.$queryRaw<JsonResultRow[]>`SELECT app_rls.session_c_create_licensee(${required(capability,"a capability")},${purpose},${required(requestId,"a request ID")},${payload}::jsonb) AS result`
    : functionName === administrationPurposes.updateLicensee
      ? await client.$queryRaw<JsonResultRow[]>`SELECT app_rls.session_c_update_licensee(${required(capability,"a capability")},${purpose},${required(requestId,"a request ID")},${payload}::jsonb) AS result`
      : functionName === administrationPurposes.deleteLicensee
        ? await client.$queryRaw<JsonResultRow[]>`SELECT app_rls.session_c_delete_licensee(${required(capability,"a capability")},${purpose},${required(requestId,"a request ID")},${payload}::jsonb) AS result`
        : functionName === administrationPurposes.createUser
          ? await client.$queryRaw<JsonResultRow[]>`SELECT app_rls.session_c_create_user(${required(capability,"a capability")},${purpose},${required(requestId,"a request ID")},${payload}::jsonb) AS result`
          : functionName === administrationPurposes.updateUser
            ? await client.$queryRaw<JsonResultRow[]>`SELECT app_rls.session_c_update_user(${required(capability,"a capability")},${purpose},${required(requestId,"a request ID")},${payload}::jsonb) AS result`
            : functionName === administrationPurposes.deleteUser
              ? await client.$queryRaw<JsonResultRow[]>`SELECT app_rls.session_c_delete_user(${required(capability,"a capability")},${purpose},${required(requestId,"a request ID")},${payload}::jsonb) AS result`
              : await client.$queryRaw<JsonResultRow[]>`SELECT app_rls.session_c_restore_manufacturer(${required(capability,"a capability")},${purpose},${required(requestId,"a request ID")},${payload}::jsonb) AS result`;
  const result = rows[0]?.result;
  if (rows.length !== 1 || !result || typeof result !== "object" || Array.isArray(result)) {
    throw new Error(`${functionName} returned an invalid database result`);
  }
  return result as T;
};

export const createLicensee = <T>(capability: string,requestId: string,input: Record<string,unknown>) => call<T>(administrationPurposes.createLicensee,capability,requestId,input);
export const updateLicensee = <T>(capability: string,requestId: string,input: Record<string,unknown>) => call<T>(administrationPurposes.updateLicensee,capability,requestId,input);
export const deleteLicensee = <T>(capability: string,requestId: string,input: Record<string,unknown>) => call<T>(administrationPurposes.deleteLicensee,capability,requestId,input);
export const createUser = <T>(capability: string,requestId: string,input: Record<string,unknown>) => call<T>(administrationPurposes.createUser,capability,requestId,input);
export const updateUser = <T>(capability: string,requestId: string,input: Record<string,unknown>) => call<T>(administrationPurposes.updateUser,capability,requestId,input);
export const deleteUser = <T>(capability: string,requestId: string,input: Record<string,unknown>) => call<T>(administrationPurposes.deleteUser,capability,requestId,input);
export const restoreManufacturer = <T>(capability: string,requestId: string,input: Record<string,unknown>) => call<T>(administrationPurposes.restoreManufacturer,capability,requestId,input);
