#!/usr/bin/env node
import { execFileSync } from "node:child_process";

const names = ["STATE_FILE", "STATE_SHA256", "SOURCE_SHA", "ROTATION_ID", "DEPLOYMENT_SHA", "TASK_DEFINITION", "IMAGE_DIGEST"];
const values = names.map((name) => process.env[`PRODUCTION_INITIAL_OVERLAP_${name}`]);
if (values.every((value) => !value)) {
  await import("./check-rotation-evidence-freshness.mjs");
} else {
  if (values.some((value) => !value)) throw new Error("Initial-overlap activation bindings are incomplete.");
  execFileSync(process.execPath, [
    "scripts/security/production-initial-overlap-activation-contract.mjs",
    "--state-file", values[0], "--state-sha256", values[1], "--source-sha", values[2],
    "--rotation-id", values[3], "--deployment-sha", values[4], "--task-definition", values[5], "--image-digest", values[6],
  ], { cwd: process.cwd(), stdio: "inherit" });
}
