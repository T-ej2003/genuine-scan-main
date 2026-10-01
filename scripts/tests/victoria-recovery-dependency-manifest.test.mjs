import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../..");
const manifest = JSON.parse(fs.readFileSync(path.join(root, "scripts/security/victoria-recovery-dependencies.json"), "utf8"));
const schema = fs.readFileSync(path.join(root, "backend/prisma/schema.prisma"), "utf8");
const classifications = new Set(["EPHEMERAL_ONBOARDING", "AUTHENTICATION_SECURITY", "IMMUTABLE_AUDIT", "BUSINESS_STATE", "SHARED_STATE", "HARD_BLOCKER", "IRRELEVANT_TO_UNACTIVATED_INVITE"]);

function modelRelations() {
  const relations = [];
  for (const model of schema.matchAll(/^model (\w+) \{([\s\S]*?)^\}/gm)) {
    const [, table, body] = model;
    for (const line of body.split("\n")) {
      const relation = line.match(/^\s*(\w+)\s+(User|Invite)\??\s+@relation(?:\((.*)\))?/);
      if (!relation) continue;
      const [, , target, args = ""] = relation;
      const column = args.match(/fields:\s*\[([^\]]+)\]/)?.[1]?.trim();
      assert.ok(column, `relation ${table}.${relation[1]} must declare a scalar FK`);
      const scalar = body.split("\n").find((candidate) => new RegExp(`^\\s*${column}\\s+`).test(candidate));
      assert.ok(scalar, `scalar ${table}.${column} must exist`);
      const nullable = new RegExp(`^\\s*${column}\\s+\\w+\\?`).test(scalar);
      const explicitAction = args.match(/onDelete:\s*(\w+)/)?.[1];
      const action = explicitAction === "Cascade" ? "CASCADE" : explicitAction === "SetNull" ? "SET NULL" : explicitAction === "Restrict" ? "RESTRICT" : undefined;
      relations.push({ table, column, target: `${target}.id`, nullable, onDelete: action || (nullable ? "SET NULL" : "RESTRICT") });
    }
  }
  return relations.sort((a, b) => `${a.table}.${a.column}`.localeCompare(`${b.table}.${b.column}`));
}

test("manifest classifies every current User and Invite relation with exact column and delete action", () => {
  const actual = modelRelations();
  const recorded = manifest.liveRelations.map(({ table, column, target, nullable, onDelete }) => ({ table, column, target, nullable, onDelete })).sort((a, b) => `${a.table}.${a.column}`.localeCompare(`${b.table}.${b.column}`));
  assert.deepEqual(recorded, actual);
  assert.equal(actual.filter(({ target }) => target === "User.id").length, 55);
  assert.equal(actual.filter(({ target }) => target === "Invite.id").length, 1);
  assert.equal(manifest.inviteRelations.length, 5);
  assert.equal(manifest.inviteRelations.filter(({ direction }) => direction === "outgoing").length, 4);
  assert.equal(manifest.inviteRelations.filter(({ direction }) => direction === "incoming").length, 1);
  assert.deepEqual(manifest.inviteRelations.map(({ classification }) => classification).sort(), ["EPHEMERAL_ONBOARDING", "HARD_BLOCKER", "HARD_BLOCKER", "IRRELEVANT_TO_UNACTIVATED_INVITE", "IRRELEVANT_TO_UNACTIVATED_INVITE"].sort());
  for (const relation of manifest.liveRelations) {
    assert.ok(classifications.has(relation.classification), `${relation.table}.${relation.column} is classified`);
    for (const field of ["ownership", "security", "expected", "delete"]) assert.ok(relation[field], `${relation.table}.${relation.column} has ${field} semantics`);
  }
});

test("migration history accounts for all historical User and Invite FK references and documents retired/replaced constraints", () => {
  const migrations = path.join(root, "backend/prisma/migrations");
  const names = { User: new Set(), Invite: new Set() };
  const references = { User: 0, Invite: 0 };
  for (const dir of fs.readdirSync(migrations)) {
    const file = path.join(migrations, dir, "migration.sql");
    if (!fs.existsSync(file)) continue;
    const sql = fs.readFileSync(file, "utf8");
    for (const match of sql.matchAll(/(?:ADD CONSTRAINT\s+"([^"]+)"\s+)?FOREIGN KEY\s*\("[^"]+"\)\s+REFERENCES\s+"(User|Invite)"\("id"\)/g)) {
      references[match[2]] += 1;
      if (match[1]) names[match[2]].add(match[1]);
    }
  }
  assert.equal(references.User, manifest.historicalMigrationUserReferences);
  assert.equal(names.User.size, manifest.historicalMigrationUserConstraintNames);
  assert.equal(names.Invite.size, manifest.historicalMigrationInviteConstraintNames);
  for (const name of manifest.retiredHistoricalConstraints) assert.ok(names.User.has(name), `retired historical FK ${name} is recorded`);
  assert.match(manifest.replacedHistoricalConstraints.PrintJob_manufacturerId_fkey, /RESTRICT/);
});

test("deletable onboarding leaves have no transitive foreign-key descendants", () => {
  const leafTables = new Set(["InviteActivationChallenge", "PasswordReset", "EmailVerificationToken", "RefreshToken"]);
  const migrations = path.join(root, "backend/prisma/migrations");
  const incoming = [];
  for (const dir of fs.readdirSync(migrations)) {
    const file = path.join(migrations, dir, "migration.sql");
    if (!fs.existsSync(file)) continue;
    const sql = fs.readFileSync(file, "utf8");
    for (const match of sql.matchAll(/(?:ADD CONSTRAINT\s+"([^"]+)"\s+)?FOREIGN KEY\s*\("([^"]+)"\)\s+REFERENCES\s+"([^"]+)"\("[^"]+"\)/g)) {
      if (leafTables.has(match[3])) incoming.push({ migration: dir, constraint: match[1] || null, column: match[2], table: match[3] });
    }
  }
  assert.deepEqual(incoming, [], "a new transitive FK under a deleted leaf must be classified before implementation can pass");
  assert.ok(manifest.inviteRelations.some(({ table, column, target }) => table === "InviteActivationChallenge" && column === "inviteId" && target === "Invite.id"));
});

test("every prune-blocking category fails closed and audit rows are never classified as deletable", () => {
  const blockers = new Set(["BUSINESS_STATE", "SHARED_STATE", "HARD_BLOCKER"]);
  assert.ok(manifest.liveRelations.some(({ classification }) => blockers.has(classification)));
  for (const relation of manifest.liveRelations.filter(({ classification }) => classification === "IMMUTABLE_AUDIT")) {
    assert.equal(relation.delete.startsWith("preserve-row"), true, `${relation.table}.${relation.column} preserves the source row`);
  }
  assert.match(manifest.policy, /UNKNOWN occupancy rejects prune/);
});
