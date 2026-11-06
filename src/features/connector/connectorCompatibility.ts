export type LatestConnectorReleaseInfo = {
  latestVersion?: string;
  minimumBuildVersion?: string | null;
  requiredProtocolVersion?: string | null;
  release?: {
    productionSignedAvailable?: boolean;
    platforms?: {
      macos?: { installationScope?: "fresh-install-only" | null } | null;
      windows?: { installationScope?: "fresh-install-only" | null } | null;
    };
  };
} | null;

type CompatibilityInput = {
  reachable: boolean;
  installerAvailable: boolean;
  buildVersion?: string | null;
  protocolVersion?: string | null;
  requiredProtocol?: string | null;
  minimumBuildVersion?: string | null;
  latestVersion?: string | null;
  installationScope?: string | null;
  backendUpdateRequired?: boolean;
};

const parts = (value?: string | null) => {
  const text = value?.trim();
  if (!text || !/^\d+\.\d+\.\d+(?:\.\d+)?$/.test(text)) return null;
  const parsed = text.split(".").map(Number);
  return parsed.every(Number.isSafeInteger) ? parsed : null;
};

const compare = (left: number[], right: number[]) => {
  for (let index = 0; index < Math.max(left.length, right.length); index += 1) {
    const difference = (left[index] || 0) - (right[index] || 0);
    if (difference) return Math.sign(difference);
  }
  return 0;
};

export const evaluateConnectorCompatibility = (input: CompatibilityInput) => {
  const installed = parts(input.buildVersion);
  const minimum = parts(input.minimumBuildVersion);
  const latest = parts(input.latestVersion);
  const freshOnly = input.installationScope === "fresh-install-only";
  const knownScope = !input.installationScope || freshOnly;
  const protocolMismatch = Boolean(input.protocolVersion && input.requiredProtocol && input.protocolVersion !== input.requiredProtocol);
  const belowMinimum = Boolean(installed && minimum && compare(installed, minimum) < 0);
  const unsupported = Boolean(input.backendUpdateRequired || protocolMismatch || belowMinimum);
  const known = Boolean(installed && minimum && input.protocolVersion && input.requiredProtocol);
  const status = unsupported ? "unsupported" : !input.reachable || !known ? "unknown" : "supported";
  const newerAvailable = Boolean(installed && latest && compare(installed, latest) < 0);
  const updateRequired = unsupported ? true : !input.reachable || !knownScope || !known ? null : false;
  const installerResolvesMinimum = !input.minimumBuildVersion || Boolean(minimum && latest && compare(latest, minimum) >= 0);
  const offerInstaller = input.installerAvailable && knownScope && Boolean(latest) && installerResolvesMinimum && (!input.reachable || !freshOnly);
  const updateAvailable = knownScope && !freshOnly && newerAvailable && offerInstaller;
  return { status, updateRequired, updateAvailable, offerInstaller, maintenanceRequired: input.reachable && unsupported && !offerInstaller } as const;
};
