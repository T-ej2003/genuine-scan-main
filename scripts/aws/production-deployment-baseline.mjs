import assert from "node:assert/strict";

const SHA = /^[a-f0-9]{40}$/;

// GitHub's completed successful workflow records are the durable authenticated
// baseline; caller arguments never participate in selecting it.
export function resolveNormalDeploymentBaseline({ candidateSha, successfulSourceShas = [], isAncestor } = {}) {
  assert.match(candidateSha || "", SHA); assert.equal(typeof isAncestor, "function");
  const eligible = [...new Set(successfulSourceShas)].filter((sha) => SHA.test(sha) && sha !== candidateSha && isAncestor(sha, candidateSha));
  return Object.freeze({ candidateSha, baselineSha: eligible[0] || null, bootstrap: eligible.length === 0 });
}
