import { Prisma, PrismaClient } from "@prisma/client";

export const RLS_READ_DATABASE_URL_ENV = "RLS_READ_DATABASE_URL";
export const STAGING_RLS_BATCHES_READ_FLAG = "MSCQR_STAGING_RLS_BATCHES_READ_ENABLED";
export const STAGING_RLS_BATCH_ALLOCATION_MAP_FLAG = "MSCQR_STAGING_RLS_BATCH_ALLOCATION_MAP_ENABLED";
export const STAGING_RLS_MANUFACTURER_PRINTERS_READ_FLAG =
  "MSCQR_STAGING_RLS_MANUFACTURER_PRINTERS_READ_ENABLED";

const stagedRlsReadFlags = [
  STAGING_RLS_BATCHES_READ_FLAG,
  STAGING_RLS_BATCH_ALLOCATION_MAP_FLAG,
  STAGING_RLS_MANUFACTURER_PRINTERS_READ_FLAG,
] as const;

const sharedTenantRlsTables = [
  "Organization",
  "Licensee",
  "User",
  "ManufacturerLicenseeLink",
] as const;

const batchDomainRlsTables = [
  "Batch",
  "InventoryStatusRollup",
  "QRCode",
  "PrintJob",
  "PrintSession",
  "PrintItem",
] as const;

const manufacturerPrinterRlsTables = [
  "PrinterRegistration",
  "Printer",
  "PrinterAttestation",
  "PrinterAgentSession",
  "PrinterProfile",
  "PrinterProfileSnapshot",
] as const;

const resolveRequiredRlsTables = (env = process.env) => {
  const required = new Set<string>();

  const batchesEnabled =
    isStagedRlsReadFlagEnabled(STAGING_RLS_BATCHES_READ_FLAG, env) ||
    isStagedRlsReadFlagEnabled(STAGING_RLS_BATCH_ALLOCATION_MAP_FLAG, env);

  const manufacturerPrintersEnabled = isStagedRlsReadFlagEnabled(
    STAGING_RLS_MANUFACTURER_PRINTERS_READ_FLAG,
    env
  );

  if (batchesEnabled || manufacturerPrintersEnabled) {
    sharedTenantRlsTables.forEach((table) => required.add(table));
  }

  if (batchesEnabled) {
    batchDomainRlsTables.forEach((table) => required.add(table));
  }

  if (manufacturerPrintersEnabled) {
    manufacturerPrinterRlsTables.forEach((table) => required.add(table));
  }

  return [...required];
};

export type RlsReadTransactionClient = Pick<Prisma.TransactionClient, "$executeRaw" | "$queryRaw"> & {
  batch: Pick<Prisma.TransactionClient["batch"], "findFirst" | "findMany" | "count">;
  inventoryStatusRollup: Pick<Prisma.TransactionClient["inventoryStatusRollup"], "findMany">;
  manufacturerLicenseeLink: Pick<Prisma.TransactionClient["manufacturerLicenseeLink"], "findMany">;
  printer: Pick<Prisma.TransactionClient["printer"], "findMany">;
  printerProfile: Pick<Prisma.TransactionClient["printerProfile"], "findUnique">;
  printerRegistration: Pick<Prisma.TransactionClient["printerRegistration"], "findFirst">;
  qRCode: Pick<Prisma.TransactionClient["qRCode"], "groupBy">;
};

export type RlsReadTransactionRunner = {
  $transaction<T>(callback: (tx: RlsReadTransactionClient) => Promise<T>): Promise<T>;
};

type ManagedRlsReadPrisma = Pick<
  PrismaClient,
  "$connect" | "$disconnect" | "$queryRaw" | "$transaction"
>;

type RlsReadPrismaFactory = (databaseUrl: string) => ManagedRlsReadPrisma;

type RlsRuntimePosture = {
  row_security_on: boolean;
  role_attributes_safe: boolean;
  no_inherited_roles: boolean;
  protected_table_count: number;
  all_tables_protected: boolean;
  all_tables_selectable: boolean;
  no_table_write_privileges: boolean;
  no_sequence_privileges: boolean;
  no_schema_create_privileges: boolean;
  no_owned_tables: boolean;
  candidate_policy_count: number;
  helper_function_count: number;
  all_helpers_executable: boolean;
};

export class RlsReadConfigurationError extends Error {
  readonly code: string;

  constructor(code: string, message: string) {
    super(message);
    this.name = "RlsReadConfigurationError";
    this.code = code;
  }
}

export class RlsReadInitializationError extends Error {
  readonly code = "RLS_READ_DATABASE_UNAVAILABLE";

  constructor() {
    super("RLS read database initialization failed");
    this.name = "RlsReadInitializationError";
  }
}

const parseBooleanEnv = (value: unknown, fallback = false) => {
  const normalized = String(value || "").trim().toLowerCase();
  if (["1", "true", "yes", "on"].includes(normalized)) return true;
  if (["0", "false", "no", "off"].includes(normalized)) return false;
  return fallback;
};

export const isStagedRlsReadFlagEnabled = (name: (typeof stagedRlsReadFlags)[number], env = process.env) =>
  parseBooleanEnv(env[name], false);

export const isAnyStagedRlsReadEnabled = (env = process.env) =>
  stagedRlsReadFlags.some((name) => isStagedRlsReadFlagEnabled(name, env));

const resolveRlsReadDatabaseConfiguration = (env = process.env) => {
  const enabled = isAnyStagedRlsReadEnabled(env);
  if (!enabled) return { enabled: false as const };

  const rlsUrl = String(env[RLS_READ_DATABASE_URL_ENV] || "").trim();
  if (!rlsUrl) {
    throw new RlsReadConfigurationError(
      "RLS_READ_DATABASE_URL_MISSING",
      `${RLS_READ_DATABASE_URL_ENV} is required when a staged RLS read route is enabled`
    );
  }

  let parsed: URL;
  try {
    parsed = new URL(rlsUrl);
  } catch {
    throw new RlsReadConfigurationError(
      "RLS_READ_DATABASE_URL_INVALID",
      `${RLS_READ_DATABASE_URL_ENV} must be a valid PostgreSQL URL`
    );
  }

  if (parsed.protocol !== "postgresql:" && parsed.protocol !== "postgres:") {
    throw new RlsReadConfigurationError(
      "RLS_READ_DATABASE_URL_INVALID_PROTOCOL",
      `${RLS_READ_DATABASE_URL_ENV} must use postgres:// or postgresql://`
    );
  }

  let databaseName = "";
  try {
    databaseName = decodeURIComponent(parsed.pathname.replace(/^\//, "")).trim();
  } catch {
    throw new RlsReadConfigurationError(
      "RLS_READ_DATABASE_URL_INVALID",
      `${RLS_READ_DATABASE_URL_ENV} must be a valid PostgreSQL URL`
    );
  }

  if (!parsed.hostname || !parsed.username) {
    throw new RlsReadConfigurationError(
      "RLS_READ_DATABASE_URL_CREDENTIAL_INCOMPLETE",
      `${RLS_READ_DATABASE_URL_ENV} must include a database host and runtime role username`
    );
  }

  if (!databaseName) {
    throw new RlsReadConfigurationError(
      "RLS_READ_DATABASE_NAME_MISSING",
      `${RLS_READ_DATABASE_URL_ENV} must include a database name`
    );
  }

  const defaultUrl = String(env.DATABASE_URL || "").trim();
  if (defaultUrl && rlsUrl === defaultUrl) {
    throw new RlsReadConfigurationError(
      "RLS_READ_DATABASE_URL_REUSES_DEFAULT",
      `${RLS_READ_DATABASE_URL_ENV} must not equal DATABASE_URL`
    );
  }

  return { enabled: true as const, databaseUrl: rlsUrl };
};

export const validateRlsReadDatabaseConfiguration = (env = process.env) => {
  const configuration = resolveRlsReadDatabaseConfiguration(env);
  return configuration.enabled ? { enabled: true as const } : configuration;
};

const defaultFactory: RlsReadPrismaFactory = (databaseUrl) =>
  new PrismaClient({
    datasources: { db: { url: databaseUrl } },
  });

let clientFactory: RlsReadPrismaFactory = defaultFactory;
let rlsReadPrisma: ManagedRlsReadPrisma | null = null;
let rlsReadTransactionRunner: RlsReadTransactionRunner | null = null;
let initializedRlsReadPrisma: ManagedRlsReadPrisma | null = null;
let initializationPromise: Promise<ManagedRlsReadPrisma> | null = null;

const createClient = (env = process.env) => {
  if (rlsReadPrisma) return rlsReadPrisma;
  const configuration = resolveRlsReadDatabaseConfiguration(env);
  if (!configuration.enabled) {
    throw new RlsReadConfigurationError(
      "RLS_READ_ROUTES_DISABLED",
      "RLS read client cannot be used while all staged RLS read routes are disabled"
    );
  }
  try {
    rlsReadPrisma = clientFactory(configuration.databaseUrl);
  } catch {
    throw new RlsReadInitializationError();
  }
  return rlsReadPrisma;
};

export const getRlsReadPrisma = (env = process.env): RlsReadTransactionRunner => {
  if (rlsReadTransactionRunner) return rlsReadTransactionRunner;
  const client = createClient(env);
  rlsReadTransactionRunner = {
    $transaction: (callback) =>
      client.$transaction((tx) => callback(tx as RlsReadTransactionClient)),
  };
  return rlsReadTransactionRunner;
};

const loadRuntimePosture = async (client: ManagedRlsReadPrisma, env = process.env) => {
  const requiredTables = resolveRequiredRlsTables(env);
  if (requiredTables.length === 0) throw new RlsReadInitializationError();

  const targetTableValues = Prisma.join(
    requiredTables.map((tableName) => Prisma.sql`(${tableName})`)
  );

  const rows = await client.$queryRaw<RlsRuntimePosture[]>`
    WITH target_tables(name) AS (
      VALUES ${targetTableValues}
    ), target_relations AS (
      SELECT c.oid, c.relowner, c.relrowsecurity, c.relforcerowsecurity
      FROM target_tables t
      JOIN pg_class c ON c.relname = t.name
      JOIN pg_namespace n ON n.oid = c.relnamespace AND n.nspname = 'public'
    ), helper_functions AS (
      SELECT p.oid
      FROM pg_proc p
      JOIN pg_namespace n ON n.oid = p.pronamespace
      WHERE n.nspname = 'app_rls'
        AND p.proname = ANY(ARRAY[
          'setting', 'current_user_id', 'current_role', 'current_licensee_id',
          'current_manufacturer_id', 'current_organization_id', 'is_platform_admin',
          'can_access_licensee', 'can_access_organization', 'can_access_batch',
          'can_access_qr', 'can_access_printer_registration', 'can_access_printer',
          'can_access_print_job', 'can_access_print_session', 'can_access_print_item',
          'can_access_printer_profile'
        ])
    )
    SELECT
      current_setting('row_security') = 'on' AS row_security_on,
      r.rolcanlogin
        AND NOT (r.rolsuper OR r.rolcreatedb OR r.rolcreaterole OR r.rolreplication OR r.rolbypassrls)
        AS role_attributes_safe,
      NOT EXISTS (SELECT 1 FROM pg_auth_members m WHERE m.member = r.oid) AS no_inherited_roles,
      (SELECT count(*)::integer FROM target_relations) AS protected_table_count,
      COALESCE((SELECT bool_and(relrowsecurity AND relforcerowsecurity) FROM target_relations), false)
        AS all_tables_protected,
      COALESCE((SELECT bool_and(has_table_privilege(current_user, oid, 'SELECT')) FROM target_relations), false)
        AS all_tables_selectable,
      NOT EXISTS (
        SELECT 1 FROM target_relations
        WHERE has_table_privilege(current_user, oid, 'INSERT')
           OR has_table_privilege(current_user, oid, 'UPDATE')
           OR has_table_privilege(current_user, oid, 'DELETE')
           OR has_table_privilege(current_user, oid, 'TRUNCATE')
           OR has_table_privilege(current_user, oid, 'REFERENCES')
           OR has_table_privilege(current_user, oid, 'TRIGGER')
      ) AS no_table_write_privileges,
      NOT EXISTS (
        SELECT 1
        FROM pg_class c
        JOIN pg_namespace n ON n.oid = c.relnamespace
        WHERE n.nspname = 'public'
          AND c.relkind = 'S'
          AND (
            has_sequence_privilege(current_user, c.oid, 'USAGE')
            OR has_sequence_privilege(current_user, c.oid, 'SELECT')
            OR has_sequence_privilege(current_user, c.oid, 'UPDATE')
          )
      ) AS no_sequence_privileges,
      NOT has_schema_privilege(current_user, 'public', 'CREATE')
        AND NOT has_schema_privilege(current_user, 'app_rls', 'CREATE')
        AS no_schema_create_privileges,
      NOT EXISTS (SELECT 1 FROM target_relations WHERE pg_has_role(r.oid, relowner, 'USAGE'))
        AS no_owned_tables,
      (
        SELECT count(*)::integer
        FROM pg_policies p
        JOIN target_tables t ON t.name = p.tablename
        WHERE p.schemaname = 'public'
          AND p.policyname LIKE 'rls_candidate_%_select'
      ) AS candidate_policy_count,
      (SELECT count(*)::integer FROM helper_functions) AS helper_function_count,
      COALESCE((SELECT bool_and(has_function_privilege(current_user, oid, 'EXECUTE')) FROM helper_functions), false)
        AS all_helpers_executable
    FROM pg_roles r
    WHERE r.rolname = current_user
  `;
  return rows[0] || null;
};

const assertRuntimePosture = (
  posture: RlsRuntimePosture | null,
  expectedProtectedTableCount: number
) => {
  if (
    !posture ||
    !posture.row_security_on ||
    !posture.role_attributes_safe ||
    !posture.no_inherited_roles ||
    posture.protected_table_count !== expectedProtectedTableCount ||
    !posture.all_tables_protected ||
    !posture.all_tables_selectable ||
    !posture.no_table_write_privileges ||
    !posture.no_sequence_privileges ||
    !posture.no_schema_create_privileges ||
    !posture.no_owned_tables ||
    posture.candidate_policy_count !== expectedProtectedTableCount ||
    posture.helper_function_count !== 17 ||
    !posture.all_helpers_executable
  ) {
    throw new RlsReadInitializationError();
  }
};

const initializeRlsReadPrismaClient = async (env = process.env) => {
  const configuration = resolveRlsReadDatabaseConfiguration(env);
  if (!configuration.enabled) return null;
  if (initializationPromise) return initializationPromise;

  const client = createClient(env);
  if (initializedRlsReadPrisma === client) return client;
  initializationPromise = (async () => {
    try {
      await client.$connect();
      const requiredTables = resolveRequiredRlsTables(env);
      assertRuntimePosture(
        await loadRuntimePosture(client, env),
        requiredTables.length
      );
      initializedRlsReadPrisma = client;
      return client;
    } catch (error) {
      await client.$disconnect().catch(() => undefined);
      if (rlsReadPrisma === client) rlsReadPrisma = null;
      if (initializedRlsReadPrisma === client) initializedRlsReadPrisma = null;
      if (error instanceof RlsReadInitializationError) throw error;
      throw new RlsReadInitializationError();
    } finally {
      initializationPromise = null;
    }
  })();
  return initializationPromise;
};

export const initializeRlsReadPrisma = async (env = process.env) =>
  (await initializeRlsReadPrismaClient(env)) ? true : null;

export const getRlsReadDatabaseHealth = async (env = process.env) => {
  if (!isAnyStagedRlsReadEnabled(env)) {
    return { configured: false, required: false, ready: true };
  }
  try {
    const client = await initializeRlsReadPrismaClient(env);
    if (!client) throw new RlsReadInitializationError();
    await client.$queryRaw`SELECT 1`;
    return { configured: true, required: true, ready: true };
  } catch (error) {
    const code =
      error instanceof RlsReadConfigurationError || error instanceof RlsReadInitializationError
        ? error.code
        : "RLS_READ_DATABASE_UNAVAILABLE";
    return { configured: Boolean(String(env[RLS_READ_DATABASE_URL_ENV] || "").trim()), required: true, ready: false, error: code };
  }
};

export const disconnectRlsReadPrisma = async () => {
  const client = rlsReadPrisma;
  rlsReadPrisma = null;
  rlsReadTransactionRunner = null;
  initializedRlsReadPrisma = null;
  initializationPromise = null;
  if (client) await client.$disconnect();
};

export const setRlsReadPrismaFactoryForTests = async (factory: RlsReadPrismaFactory | null) => {
  if (process.env.NODE_ENV !== "test") {
    throw new Error("RLS read Prisma factory injection is test-only");
  }
  await disconnectRlsReadPrisma();
  clientFactory = factory || defaultFactory;
};
