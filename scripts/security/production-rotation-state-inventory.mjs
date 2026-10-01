import { spawnSync } from "node:child_process";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { existsSync } from "node:fs";
const { STAGE_B } = await import(existsSync(new URL("../aws/production-green-stage-b-contract.mjs", import.meta.url)) ? "../aws/production-green-stage-b-contract.mjs" : "./production-green-stage-b-contract.mjs");

export function buildRotationInventorySql() {
  return "BEGIN; SET TRANSACTION READ ONLY; SET LOCAL statement_timeout = '15000ms'; SET LOCAL lock_timeout = '2000ms'; SELECT app_rls.production_rotation_inventory() AS inventory; ROLLBACK;";
}

export function executeProductionRotationInventory({ spawn = spawnSync, env = process.env } = {}) {
  if (env.ROTATION_INVENTORY_APPROVED !== "true" || env.ROTATION_INVENTORY_OPERATION !== STAGE_B.inventoryOperation) throw new Error("read-only inventory requires the fixed authenticated aggregate operation");
  if (!env.DATABASE_URL) throw new Error("DATABASE_URL must be provided by the approved read-only runtime");
  const result = spawn("psql", ["--no-psqlrc", "--set", "ON_ERROR_STOP=1", "--quiet", "--tuples-only", "--no-align", env.DATABASE_URL, "--command", buildRotationInventorySql()], { encoding: "utf8", stdio: ["ignore", "pipe", "pipe"], env: { ...env, PSQL_HISTORY: "/dev/null", PGAPPNAME: "mscqr-production-rotation-read-only-inventory" } });
  if (result.error || result.signal || result.status !== 0) throw new Error("read-only rotation inventory query failed");
  try { return JSON.parse(String(result.stdout || "").trim()); } catch { throw new Error("read-only rotation inventory returned malformed metadata"); }
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) console.log(JSON.stringify(executeProductionRotationInventory()));
