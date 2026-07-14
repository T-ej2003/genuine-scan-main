#!/usr/bin/env node
"use strict";

const { PrismaClient } = require("@prisma/client");

const BEGIN = "MSCQR_DB_IDENTITY_BEGIN";
const END = "MSCQR_DB_IDENTITY_END";
const QUERY = "SELECT current_database() AS database_name, current_user AS database_user";

function identityBlock(identity) {
  if (typeof identity?.database_name !== "string" || typeof identity?.database_user !== "string") {
    throw new Error("runtime identity unavailable");
  }
  return `${BEGIN}\n${JSON.stringify({ database_name: identity.database_name, database_user: identity.database_user })}\n${END}\n`;
}

async function runRuntimeDatabaseIdentity({
  clientFactory = () => new PrismaClient({ log: [] }),
  stdout = process.stdout,
  stderr = process.stderr,
} = {}) {
  let client;
  let disconnected = false;
  try {
    client = clientFactory();
    const rows = await client.$queryRawUnsafe(QUERY);
    await client.$disconnect();
    disconnected = true;
    stdout.write(identityBlock(rows?.[0]));
    return 0;
  } catch {
    if (client && !disconnected) try { await client.$disconnect(); } catch { /* fail closed without additional output */ }
    stderr.write(`${JSON.stringify({ status: "blocked", code: "runtime_identity_probe_failed" })}\n`);
    return 2;
  }
}

if (require.main === module) {
  runRuntimeDatabaseIdentity()
    .then((exitCode) => { process.exitCode = exitCode; })
    .catch(() => { process.exitCode = 2; });
}

module.exports = { BEGIN, END, QUERY, identityBlock, runRuntimeDatabaseIdentity };
