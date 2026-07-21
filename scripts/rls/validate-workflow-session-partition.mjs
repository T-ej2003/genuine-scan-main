import fs from "node:fs";
import crypto from "node:crypto";
import path from "node:path";
import { fileURLToPath } from "node:url";

const repoRoot = path.resolve(fileURLToPath(new URL("../..", import.meta.url)));
const programRoot = path.join(repoRoot, "documents/security/rls-program");
const read = (name) => JSON.parse(fs.readFileSync(path.join(programRoot, name), "utf8"));
const workflowIds = read("workflows.json").workflows.map((workflow) => workflow.id);
const partition = read("workflow-three-session-partition.json");
const ownership = ["session-a", "session-b", "session-c"].map((id) => read(`workflow-ownership-${id}.json`));
const workflowSetSha256 = (ids) => crypto.createHash("sha256").update(`${[...ids].sort().join("\n")}\n`).digest("hex");
const counts = new Map();
for (const row of partition.assignments) counts.set(row.workflowId, (counts.get(row.workflowId) || 0) + 1);
const source = new Set(workflowIds);
const missing = workflowIds.filter((id) => !counts.has(id));
const duplicate = [...counts].filter(([, count]) => count !== 1).map(([id]) => id);
const unknown = [...counts.keys()].filter((id) => !source.has(id));
const generic = partition.assignments.filter((row) => !row.contract?.trim() || /fallback|catch.?all|remaining|misc/i.test(`${row.waveId}:${row.assignmentRuleId}`));
const sessionIds = new Set(partition.sessions.map((session) => session.id));
const waveIds = new Set(partition.waves.map((wave) => wave.id));
const waveSessionById = new Map(partition.waves.map((wave) => [wave.id, wave.sessionId]));
const invalidReferences = partition.assignments.filter((row) => !sessionIds.has(row.sessionId) || !waveIds.has(row.waveId) || waveSessionById.get(row.waveId) !== row.sessionId);
const ownershipIds = ownership.flatMap((session) => session.workflowIds);
const ownershipSet = new Set(ownershipIds);
const productionFileOwners = new Map();
const testFileOwners = new Map();
for (const session of ownership) {
  for (const file of session.productionFiles) productionFileOwners.set(file, [...(productionFileOwners.get(file) || []), session.id]);
  for (const file of session.existingTestFiles || []) testFileOwners.set(file, [...(testFileOwners.get(file) || []), session.id]);
}
const productionOverlap = [...productionFileOwners].filter(([, owners]) => owners.length > 1).map(([file, owners]) => ({ file, owners }));
const testOverlap = [...testFileOwners].filter(([, owners]) => owners.length > 1).map(([file, owners]) => ({ file, owners }));
const ownershipAssignmentMismatch = ownership.flatMap((session) => {
  const assigned = partition.assignments.filter((row) => row.sessionId === session.id).map((row) => row.workflowId).sort();
  return JSON.stringify(assigned) === JSON.stringify([...session.workflowIds].sort()) ? [] : [session.id];
});
const familyCoverageMismatch = ownership.flatMap((session) => {
  const familyIds = session.workflowFamilies.flatMap((family) => family.workflowIds).sort();
  return JSON.stringify(familyIds) === JSON.stringify([...session.workflowIds].sort()) && new Set(familyIds).size === familyIds.length ? [] : [session.id];
});
const sessionB = ownership.find((session) => session.id === "session-b");
const missingOwnedFiles = ownership.flatMap((session) => [...session.productionFiles, ...(session.existingTestFiles || [])]
  .filter((file) => !fs.existsSync(path.join(repoRoot, file)))
  .map((file) => `${session.id}:${file}`));
const failures = {
  schemaVersion: partition.schemaVersion === 2 ? [] : [partition.schemaVersion],
  sessionIds: JSON.stringify([...sessionIds].sort()) === JSON.stringify(["session-a", "session-b", "session-c"]) ? [] : [...sessionIds],
  duplicateSessionIds: partition.sessions.length === sessionIds.size ? [] : partition.sessions.map((session) => session.id),
  duplicateWaveIds: partition.waves.length === waveIds.size ? [] : partition.waves.map((wave) => wave.id),
  authoritativeCount: workflowIds.length === 428 ? [] : [workflowIds.length],
  assignmentCount: partition.assignments.length === 428 ? [] : [partition.assignments.length],
  missing,
  duplicate,
  unknown,
  generic: generic.map((row) => row.workflowId),
  invalidReferences: invalidReferences.map((row) => row.workflowId),
  ownershipMissing: workflowIds.filter((id) => !ownershipSet.has(id)),
  ownershipDuplicate: ownershipIds.filter((id, index) => ownershipIds.indexOf(id) !== index),
  ownershipAssignmentMismatch,
  familyCoverageMismatch,
  productionOverlap,
  testOverlap,
  missingOwnedFiles,
  coordinationBaseMismatch: ownership.filter((session) => session.coordinationBaseCommit !== partition.coordinationBaseCommit).map((session) => session.id),
  sessionBWorkflowOwnershipChanged: workflowSetSha256(sessionB.workflowIds) === partition.validationSummary.sessionBWorkflowSetSha256 && partition.validationSummary.sessionBWorkflowOwnershipPreserved ? [] : [workflowSetSha256(sessionB.workflowIds)],
};
if (Object.values(failures).some((rows) => rows.length)) throw new Error(JSON.stringify(failures, null, 2));
console.log(JSON.stringify({ valid: true, coordinationBaseCommit: partition.coordinationBaseCommit, workflows: workflowIds.length, assignments: partition.assignments.length, missing: 0, duplicate: 0, unknown: 0, genericCatchAll: 0, sessionCounts: partition.validationSummary.sessionCounts, waveCounts: partition.validationSummary.waveCounts, sessionBWorkflowSetSha256: partition.validationSummary.sessionBWorkflowSetSha256, editableProductionFileOverlap: 0, editableTestFileOverlap: 0 }));
