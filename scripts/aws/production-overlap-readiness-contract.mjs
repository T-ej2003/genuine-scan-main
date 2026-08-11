export const READY_FOR_OVERLAP_DEPLOYMENT_STAGES = Object.freeze([
  "imageAuthorization",
  "iamPreflight",
  "rootDrop",
  "releaseIdentity",
  "verifierIdentity",
  "stageA",
  "artifactSigning",
  "overlapTaskDefinition",
  "inventory",
  "rotationPrepare",
]);

export function assertReadyForOverlapDeployment(evidence) {
  for (const stage of READY_FOR_OVERLAP_DEPLOYMENT_STAGES) {
    if (evidence?.[stage] !== true) throw new Error(`READY_FOR_OVERLAP_DEPLOYMENT requires ${stage}=true`);
  }
  if (evidence.rotationPrepared !== true) throw new Error("READY_FOR_OVERLAP_DEPLOYMENT requires rotationPrepared=true");
  if (evidence.ecsUpdateServiceCount !== 0) throw new Error("READY_FOR_OVERLAP_DEPLOYMENT must be evaluated before ECS UpdateService");
  return { readyForOverlapDeployment: true, stages: [...READY_FOR_OVERLAP_DEPLOYMENT_STAGES] };
}
