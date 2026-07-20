import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const repoRoot = path.resolve(fileURLToPath(new URL("../..", import.meta.url)));
const programRoot = path.join(repoRoot, "documents/security/rls-program");
const read = (name) => JSON.parse(fs.readFileSync(path.join(programRoot, name), "utf8"));
const workflowIds = read("workflows.json").workflows.map((workflow) => workflow.id);
const partition = read("workflow-two-session-partition.json");
const ownership = [read("workflow-ownership-session-a.json"), read("workflow-ownership-session-b.json")];
const counts = new Map();
for (const row of partition.assignments) counts.set(row.workflowId, (counts.get(row.workflowId) || 0) + 1);
const source = new Set(workflowIds);
const missing = workflowIds.filter((id) => !counts.has(id));
const duplicate = [...counts].filter(([, count]) => count !== 1).map(([id]) => id);
const unknown = [...counts.keys()].filter((id) => !source.has(id));
const generic = partition.assignments.filter((row) => !row.contract?.trim() || /fallback|catch.?all|remaining|misc/i.test(`${row.waveId}:${row.assignmentRuleId}`));
const sessionIds = new Set(partition.sessions.map((session) => session.id));
const waveIds = new Set(partition.waves.map((wave) => wave.id));
const invalidReferences = partition.assignments.filter((row) => !sessionIds.has(row.sessionId) || !waveIds.has(row.waveId));
const ownershipIds = ownership.flatMap((session) => session.workflowIds);
const ownershipSet = new Set(ownershipIds);
const productionOverlap = ownership[0].productionFiles.filter((file) => ownership[1].productionFiles.includes(file));
const failures = {
  authoritativeCount: workflowIds.length === 428 ? [] : [workflowIds.length],
  assignmentCount: partition.assignments.length === 428 ? [] : [partition.assignments.length],
  missing,
  duplicate,
  unknown,
  generic: generic.map((row) => row.workflowId),
  invalidReferences: invalidReferences.map((row) => row.workflowId),
  ownershipMissing: workflowIds.filter((id) => !ownershipSet.has(id)),
  ownershipDuplicate: ownershipIds.filter((id, index) => ownershipIds.indexOf(id) !== index),
  productionOverlap,
  foundationMismatch: ownership.filter((session) => session.foundationCommit !== partition.foundationCommit).map((session) => session.id),
};
if (Object.values(failures).some((rows) => rows.length)) throw new Error(JSON.stringify(failures, null, 2));
console.log(JSON.stringify({ valid: true, foundationCommit: partition.foundationCommit, workflows: workflowIds.length, assignments: partition.assignments.length, missing: 0, duplicate: 0, unknown: 0, genericCatchAll: 0, sessionCounts: partition.validationSummary.sessionCounts, waveCounts: partition.validationSummary.waveCounts, editableProductionFileOverlap: 0 }));
