import { WEB_RELEASE, buildWebImageAuthorization } from "./production-web-release-contract.mjs";

// This is deliberately a library boundary, not an operator CLI: only the governed
// evidence producer may reach it after it has authenticated publication state.
export function buildGovernedWebImageAuthorization({ sourceSha, evidence, signature, stageBAuthorization, now, verify } = {}) {
  const impact = stageBAuthorization?.imageReuseEvidence;
  if (typeof impact?.webPublicationRequired !== "boolean" || impact.toolingSha !== sourceSha || evidence?.sourceSha !== sourceSha || evidence?.reviewer !== WEB_RELEASE.reviewer) {
    throw new Error("Governed web authorization requires authenticated Stage-B impact.");
  }
  return buildWebImageAuthorization({ sourceSha, evidence, signature, imageImpact: impact, reviewer: WEB_RELEASE.reviewer, now, verify });
}
