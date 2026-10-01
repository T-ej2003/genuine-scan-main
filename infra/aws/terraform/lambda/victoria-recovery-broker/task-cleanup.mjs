const OPERATION = "VICTORIA_FAILED_ONBOARDING_RECOVERY_V1";
const FAMILY = "mscqr-production-victoria-recovery";
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const SHA = /^[a-f0-9]{40}$/;
const ACTIVE = new Set(["PROVISIONING", "PENDING", "ACTIVATING", "RUNNING"]);
const STOPPING = new Set(["DEACTIVATING", "STOPPING", "DEPROVISIONING"]);

export async function stopVictoriaRecoveryTasks({ cluster, nonce, sourceSha, knownTaskArns = [], listTasks, describeTasks, stopTask, waitStopped }) {
  let failed = !cluster || !UUID.test(nonce || "") || !SHA.test(sourceSha || "");
  let listed = [];
  try {
    const response = await listTasks({ startedBy: nonce });
    listed = response.taskArns || [];
    if (response.nextToken || listed.some((arn) => typeof arn !== "string")) failed = true;
  } catch { failed = true; }
  const taskArns = [...new Set([...knownTaskArns, ...listed])];
  if (taskArns.length > 100) return { taskStopped: false, taskCleanupFailed: true, stoppedTaskCount: 0 };
  if (!taskArns.length) return { taskStopped: !failed, taskCleanupFailed: failed, stoppedTaskCount: 0 };

  let response;
  try { response = await describeTasks({ cluster, tasks: taskArns, include: ["TAGS"] }); }
  catch { return { taskStopped: false, taskCleanupFailed: true, stoppedTaskCount: 0 }; }
  if (response.failures?.length || response.tasks?.length !== taskArns.length) failed = true;
  let stoppedTaskCount = 0;
  for (const task of response.tasks || []) {
    const tags = Object.fromEntries((task.tags || []).map(({ key, value }) => [key, value]));
    if (task.clusterArn !== cluster || task.group !== `family:${FAMILY}` || task.startedBy !== nonce
        || tags.Operation !== OPERATION || tags.AuthorizationNonce !== nonce || tags.SourceSha !== sourceSha) {
      failed = true;
      continue;
    }
    if (task.lastStatus === "STOPPED") { stoppedTaskCount += 1; continue; }
    if (!ACTIVE.has(task.lastStatus) && !STOPPING.has(task.lastStatus)) { failed = true; continue; }
    if (ACTIVE.has(task.lastStatus)) {
      try { await stopTask({ cluster, task: task.taskArn, reason: OPERATION }); }
      catch {
        if (!(await waitStopped(task.taskArn))) { failed = true; continue; }
        stoppedTaskCount += 1;
        continue;
      }
    }
    if (await waitStopped(task.taskArn)) stoppedTaskCount += 1;
    else failed = true;
  }
  if (taskArns.length > 1) failed = true;
  return { taskStopped: !failed && stoppedTaskCount === taskArns.length, taskCleanupFailed: failed, stoppedTaskCount };
}

export async function persistVictoriaRecoveryCleanup({ receipt, putEvidence }) {
  await putEvidence(receipt);
  if (receipt.networkAuthorityRevoked !== true || receipt.taskStopped !== true) {
    throw new Error("RECOVERY_CLEANUP_INCOMPLETE_EVIDENCE_PERSISTED");
  }
  return true;
}
