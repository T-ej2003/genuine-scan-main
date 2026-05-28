#!/usr/bin/env node
import fs from "node:fs";

const usage = () => {
  console.error(`Usage:
  node scripts/dr/check-asg-target-health-accounting.mjs --asg-json <file> --target-health-json <file> [--desired <n>] [--out-json <file>] [--no-fail]
  node scripts/dr/check-asg-target-health-accounting.mjs --self-test`);
};

const args = process.argv.slice(2);
const options = {};
for (let index = 0; index < args.length; index += 1) {
  const arg = args[index];
  if (arg === "--self-test" || arg === "--no-fail") {
    options[arg.slice(2)] = true;
    continue;
  }
  if (arg.startsWith("--")) {
    options[arg.slice(2)] = args[index + 1];
    index += 1;
  }
}

const readJson = (filePath) => JSON.parse(fs.readFileSync(filePath, "utf8"));

export const summarizeAsgTargetHealth = ({ asgPayload, targetHealthPayload, desiredCapacity }) => {
  const asg = asgPayload.AutoScalingGroups?.[0];
  if (!asg) throw new Error("ASG payload does not contain AutoScalingGroups[0].");

  const desired = Number.isInteger(desiredCapacity) ? desiredCapacity : Number(asg.DesiredCapacity);
  if (!Number.isInteger(desired) || desired < 1) throw new Error("Desired capacity must be a positive integer.");

  const asgInstances = (asg.Instances || [])
    .map((instance) => ({
      id: String(instance.InstanceId || ""),
      lifecycle: String(instance.LifecycleState || "unknown"),
      asgHealth: String(instance.HealthStatus || "unknown"),
    }))
    .filter((instance) => instance.id);

  const asgIds = new Set(asgInstances.map((instance) => instance.id));
  const targetDescriptions = targetHealthPayload.TargetHealthDescriptions || [];
  const targetById = new Map();
  for (const description of targetDescriptions) {
    const id = String(description.Target?.Id || "");
    if (!id) continue;
    targetById.set(id, {
      id,
      port: description.Target?.Port ?? null,
      state: String(description.TargetHealth?.State || "unknown"),
      reason: String(description.TargetHealth?.Reason || ""),
      description: String(description.TargetHealth?.Description || ""),
    });
  }

  const healthyAsgTargets = [];
  const unhealthyAsgTargets = [];
  for (const instance of asgInstances) {
    const target = targetById.get(instance.id);
    if (target?.state === "healthy") {
      healthyAsgTargets.push({ ...instance, ...target });
    } else {
      unhealthyAsgTargets.push({
        ...instance,
        id: instance.id,
        port: target?.port ?? null,
        state: target?.state || "not_registered",
        reason: target?.reason || "Target.NotRegistered",
        description: target?.description || "Current ASG instance is not present as a target.",
      });
    }
  }

  const legacyOrNonAsgHealthyTargets = targetDescriptions
    .map((description) => ({
      id: String(description.Target?.Id || ""),
      port: description.Target?.Port ?? null,
      state: String(description.TargetHealth?.State || "unknown"),
      reason: String(description.TargetHealth?.Reason || ""),
    }))
    .filter((target) => target.id && !asgIds.has(target.id) && target.state === "healthy");

  return {
    desiredCapacity: desired,
    currentAsgInstanceIds: asgInstances.map((instance) => instance.id),
    healthyAsgTargetIds: healthyAsgTargets.map((target) => target.id),
    unhealthyAsgTargets,
    legacyOrNonAsgHealthyTargetIds: legacyOrNonAsgHealthyTargets.map((target) => target.id),
    totalHealthyTargetIds: targetDescriptions
      .filter((description) => description.TargetHealth?.State === "healthy")
      .map((description) => String(description.Target?.Id || ""))
      .filter(Boolean),
    asgHealthyTargetCount: healthyAsgTargets.length,
    ready: healthyAsgTargets.length >= desired,
  };
};

const printSummary = (summary) => {
  console.log(`DESIRED_CAPACITY=${summary.desiredCapacity}`);
  console.log(`CURRENT_ASG_INSTANCE_IDS=${summary.currentAsgInstanceIds.join(",") || "none"}`);
  console.log(`HEALTHY_ASG_TARGET_IDS=${summary.healthyAsgTargetIds.join(",") || "none"}`);
  console.log(
    `UNHEALTHY_ASG_TARGETS=${
      summary.unhealthyAsgTargets
        .map((target) => `${target.id}:${target.state}${target.reason ? `:${target.reason}` : ""}`)
        .join(",") || "none"
    }`
  );
  console.log(`LEGACY_OR_NON_ASG_HEALTHY_TARGET_IDS=${summary.legacyOrNonAsgHealthyTargetIds.join(",") || "none"}`);
  console.log(`TOTAL_HEALTHY_TARGET_IDS=${summary.totalHealthyTargetIds.join(",") || "none"}`);
  console.log(`ASG_HEALTHY_TARGET_COUNT=${summary.asgHealthyTargetCount}`);
  console.log(`ASG_TARGET_HEALTH_READY=${summary.ready ? "true" : "false"}`);
};

const assertSelfTest = (name, summary, expectedReady) => {
  if (summary.ready !== expectedReady) {
    throw new Error(`${name} expected ready=${expectedReady}, got ${summary.ready}`);
  }
};

const runSelfTest = () => {
  const asgPayload = {
    AutoScalingGroups: [
      {
        DesiredCapacity: 2,
        Instances: [
          { InstanceId: "i-asg-a", LifecycleState: "InService", HealthStatus: "Healthy" },
          { InstanceId: "i-asg-b", LifecycleState: "InService", HealthStatus: "Healthy" },
        ],
      },
    ],
  };
  const maskedByLegacy = summarizeAsgTargetHealth({
    asgPayload,
    targetHealthPayload: {
      TargetHealthDescriptions: [
        { Target: { Id: "i-asg-a", Port: 80 }, TargetHealth: { State: "healthy" } },
        { Target: { Id: "i-legacy", Port: 80 }, TargetHealth: { State: "healthy" } },
        {
          Target: { Id: "i-asg-b", Port: 80 },
          TargetHealth: { State: "unhealthy", Reason: "Target.FailedHealthChecks" },
        },
      ],
    },
    desiredCapacity: 2,
  });
  assertSelfTest("legacy healthy target must not mask one unhealthy ASG target", maskedByLegacy, false);

  const twoAsgHealthyPlusLegacy = summarizeAsgTargetHealth({
    asgPayload,
    targetHealthPayload: {
      TargetHealthDescriptions: [
        { Target: { Id: "i-asg-a", Port: 80 }, TargetHealth: { State: "healthy" } },
        { Target: { Id: "i-asg-b", Port: 80 }, TargetHealth: { State: "healthy" } },
        { Target: { Id: "i-legacy", Port: 80 }, TargetHealth: { State: "healthy" } },
      ],
    },
    desiredCapacity: 2,
  });
  assertSelfTest("two current ASG healthy targets should pass even with legacy target registered", twoAsgHealthyPlusLegacy, true);
  console.log("ASG target-health accounting self-test passed.");
};

if (options["self-test"]) {
  runSelfTest();
  process.exit(0);
}

if (!options["asg-json"] || !options["target-health-json"]) {
  usage();
  process.exit(2);
}

const summary = summarizeAsgTargetHealth({
  asgPayload: readJson(options["asg-json"]),
  targetHealthPayload: readJson(options["target-health-json"]),
  desiredCapacity: options.desired ? Number(options.desired) : undefined,
});

if (options["out-json"]) {
  fs.writeFileSync(options["out-json"], `${JSON.stringify(summary, null, 2)}\n`);
}
printSummary(summary);

if (!summary.ready && !options["no-fail"]) {
  process.exit(3);
}
