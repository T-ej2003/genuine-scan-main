import { randomInt } from "crypto";
import { getTokenHashSecretSet } from "../../utils/secretConfig";
import { hmacSha256Hex } from "../../utils/security";

type ActivationBinding = {
  challengeId: string;
  userId: string;
  inviteId: string;
  email: string;
};

export const newInviteActivationCode = () => randomInt(0, 1_000_000).toString().padStart(6, "0");

const verifierMessage = (binding: ActivationBinding, code: string) =>
  JSON.stringify(["INVITE_ACTIVATION:v1", binding.challengeId, binding.userId, binding.inviteId, binding.email, code]);

export const inviteActivationVerifier = (binding: ActivationBinding, code: string) => {
  const { current } = getTokenHashSecretSet();
  return `${current.id}:${hmacSha256Hex(verifierMessage(binding, code), current.value)}`;
};

export const inviteActivationVerifierCandidates = (binding: ActivationBinding, code: string) =>
  getTokenHashSecretSet().all.map((secret) =>
    `${secret.id}:${hmacSha256Hex(verifierMessage(binding, code), secret.value)}`
  );
