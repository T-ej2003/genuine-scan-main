const assert = require("assert");

const { assessSignedReplay } = require("../dist/services/verificationReplayService");

const firstSigned = assessSignedReplay({
  signedTokenPresent: true,
  replayEpoch: 1,
  tokenReplayEpoch: 1,
  signedFirstSeenAt: null,
  lastSignedVerificationAt: null,
  lastSignedVerificationIpHash: null,
  lastSignedVerificationDeviceHash: null,
  actorIpHash: "ip-hash-1",
  actorDeviceHash: "device-hash-1",
  signals: {
    recentScanCount10m: 1,
    ipVelocityCount10m: 1,
    distinctDeviceCount24h: 1,
    distinctUntrustedDeviceCount24h: 0,
  },
});

assert.strictEqual(firstSigned.replayState, "FIRST_SIGNED_USE", "first signed verification should open the replay epoch");
assert.strictEqual(firstSigned.reviewRequired, false, "first signed verification should not be downgraded by replay logic");

const sameContextRepeat = assessSignedReplay({
  signedTokenPresent: true,
  replayEpoch: 1,
  tokenReplayEpoch: 1,
  signedFirstSeenAt: "2026-04-05T09:00:00.000Z",
  lastSignedVerificationAt: "2026-04-05T09:03:00.000Z",
  lastSignedVerificationIpHash: "ip-hash-1",
  lastSignedVerificationDeviceHash: "device-hash-1",
  actorIpHash: "ip-hash-1",
  actorDeviceHash: "device-hash-1",
  signals: {
    seenOnCurrentDeviceBefore: true,
    previousScanSameDevice: true,
    recentScanCount10m: 2,
    ipVelocityCount10m: 1,
    distinctDeviceCount24h: 1,
    distinctUntrustedDeviceCount24h: 0,
  },
  now: new Date("2026-04-05T09:05:00.000Z"),
});

assert.strictEqual(sameContextRepeat.replayState, "SAME_CONTEXT_REPEAT", "same-context signed reuse should stay in repeat state");
assert.strictEqual(sameContextRepeat.reviewRequired, false, "same-context repeat should not trigger replay review");

const changedContextRepeat = assessSignedReplay({
  signedTokenPresent: true,
  replayEpoch: 1,
  tokenReplayEpoch: 1,
  signedFirstSeenAt: "2026-04-05T09:00:00.000Z",
  lastSignedVerificationAt: "2026-04-05T09:03:00.000Z",
  lastSignedVerificationIpHash: "ip-hash-1",
  lastSignedVerificationDeviceHash: "device-hash-1",
  actorIpHash: "ip-hash-2",
  actorDeviceHash: "device-hash-2",
  customerUserId: null,
  signals: {
    seenOnCurrentDeviceBefore: false,
    previousScanSameDevice: false,
    recentScanCount10m: 3,
    ipVelocityCount10m: 3,
    distinctDeviceCount24h: 2,
    distinctUntrustedDeviceCount24h: 1,
    distinctCountryCount24h: 2,
    distinctUntrustedCountryCount24h: 1,
    crossCodeCorrelation24h: 1,
    deviceGraphOverlap24h: 1,
  },
  now: new Date("2026-04-05T09:06:00.000Z"),
});

assert.strictEqual(
  changedContextRepeat.replayState,
  "RAPID_CHANGED_CONTEXT_REPEAT",
  "changed-context rapid reuse should escalate to the highest replay state"
);
assert.strictEqual(changedContextRepeat.reviewRequired, true, "changed-context signed reuse should require review");
assert.strictEqual(changedContextRepeat.stepUpRecommended, true, "anonymous changed-context replay should recommend step-up");
assert(
  changedContextRepeat.reasons.some((reason) => /different scan context/i.test(reason) || /unusually quickly/i.test(reason)),
  "changed-context replay should explain why it was downgraded"
);

const lowSignalRepeat = assessSignedReplay({
  signedTokenPresent: true,
  replayEpoch: 1,
  tokenReplayEpoch: 1,
  signedFirstSeenAt: "2026-04-05T09:00:00.000Z",
  lastSignedVerificationAt: "2026-04-05T09:05:00.000Z",
  lastSignedVerificationIpHash: null,
  lastSignedVerificationDeviceHash: null,
  actorIpHash: null,
  actorDeviceHash: null,
  customerUserId: null,
  signals: {
    recentScanCount10m: 1,
    ipVelocityCount10m: 0,
    distinctDeviceCount24h: 0,
    distinctUntrustedDeviceCount24h: 0,
    distinctCountryCount24h: 0,
    distinctUntrustedCountryCount24h: 0,
  },
  now: new Date("2026-04-05T09:10:00.000Z"),
});

assert.strictEqual(
  lowSignalRepeat.replayState,
  "SAME_CONTEXT_REPEAT",
  "low-signal signed repeats should not be mislabeled as changed-context reuse"
);
assert.strictEqual(lowSignalRepeat.reviewRequired, false, "low-signal repeats should stay outside replay review");
assert.strictEqual(lowSignalRepeat.stepUpRecommended, false, "low-signal repeats should not trigger anonymous step-up");

console.log("verification replay service tests passed");
