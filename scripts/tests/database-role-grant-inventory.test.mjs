import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import test from "node:test";

const repoRoot = path.resolve(new URL("../..", import.meta.url).pathname);
const schemaPath = path.join(repoRoot, "backend/prisma/schema.prisma");
const templatePath = path.join(repoRoot, "documents/security/mscqr_staging_database_role_separation_template_2026-07-10.sql");
const inventoryPath = path.join(repoRoot, "documents/security/MSCQR_DATABASE_ROLE_GRANT_INVENTORY_2026-07-10.md");

const listSourceFiles = (root) => {
  const files = [];
  const walk = (directory) => {
    for (const entry of fs.readdirSync(directory, { withFileTypes: true })) {
      const entryPath = path.join(directory, entry.name);
      if (entry.isDirectory()) walk(entryPath);
      else if (/\.(?:ts|js)$/.test(entry.name)) files.push(entryPath);
    }
  };
  walk(root);
  return files;
};

const applicationModels = () => {
  const schema = fs.readFileSync(schemaPath, "utf8");
  return Object.fromEntries(
    [...schema.matchAll(/^model\s+(\w+)\s*\{/gm)].map((match) => {
      const model = match[1];
      return [model[0].toLowerCase() + model.slice(1), model];
    })
  );
};

const directWriteInventory = () => {
  const delegates = applicationModels();
  const inventory = new Map();
  for (const root of ["backend/src", "backend/scripts", "backend/prisma"]) {
    for (const filePath of listSourceFiles(path.join(repoRoot, root))) {
      const source = fs.readFileSync(filePath, "utf8");
      for (const match of source.matchAll(/\b\w+\.(\w+)\.(createMany|create|updateMany|update|upsert|deleteMany|delete)\s*\(/g)) {
        const model = delegates[match[1]];
        if (!model) continue;
        const privileges = inventory.get(model) || new Set();
        if (match[2].startsWith("create")) privileges.add("INSERT");
        if (match[2].startsWith("update")) privileges.add("UPDATE");
        if (match[2].startsWith("delete")) privileges.add("DELETE");
        if (match[2] === "upsert") {
          privileges.add("INSERT");
          privileges.add("UPDATE");
        }
        inventory.set(model, privileges);
      }
    }
  }
  return inventory;
};

const grantList = (template, privilege) => {
  const match = template.match(new RegExp(`GRANT ${privilege} ON TABLE\\s+([\\s\\S]*?)\\s+TO :"mscqr_app_role";`));
  assert(match, `missing explicit app ${privilege} grant list`);
  return new Set([...match[1].matchAll(/"([A-Za-z0-9_]+)"/g)].map((entry) => entry[1]));
};

test("database role app DML grants cover all direct backend write paths without ALL PRIVILEGES", () => {
  const template = fs.readFileSync(templatePath, "utf8");
  const inventory = directWriteInventory();
  for (const privilege of ["INSERT", "UPDATE", "DELETE"]) {
    const expected = new Set([...inventory].filter(([, privileges]) => privileges.has(privilege)).map(([model]) => model));
    assert.deepEqual(
      [...grantList(template, privilege)].sort(),
      [...expected].sort(),
      `${privilege} grants must exactly match direct backend write paths across src, scripts, and Prisma seed`
    );
  }
  assert.doesNotMatch(template, /ALL PRIVILEGES/i);
});

test("human grant inventory documents tables, sequences, functions, and raw-SQL ownership", () => {
  const inventory = fs.readFileSync(inventoryPath, "utf8");
  assert.match(inventory, /backend\/src/);
  assert.match(inventory, /backend\/scripts/);
  assert.match(inventory, /backend\/prisma\/seed\.ts/);
  assert.match(inventory, /No sequence grants are currently required/);
  assert.match(inventory, /hotEventPartitionService/);
  assert.match(inventory, /RLS read role.*SELECT-only/i);
  for (const model of ["ActionIdempotencyKey", "BatchPrintPackToken", "QRCode", "UserMfaFactor"]) {
    assert.match(inventory, new RegExp(`\\b${model}\\b`));
  }
});
