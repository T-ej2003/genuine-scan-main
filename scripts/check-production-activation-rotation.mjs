#!/usr/bin/env node
import { execFileSync } from "node:child_process";

const names = ["STATE_FILE", "STATE_SHA256", "SOURCE_SHA", "ROTATION_ID", "DEPLOYMENT_SHA", "TASK_DEFINITION", "IMAGE_DIGEST"];
const values = names.map((name) => process.env[`PRODUCTION_INITIAL_OVERLAP_${name}`]);
const contract = process.env.PRODUCTION_ACTIVATION_ROTATION_CONTRACT;
if (contract === "STRICT_FINAL_ROTATION") {
  if (values.some((value) => value)) throw new Error("Strict final rotation cannot consume initial-overlap bindings.");
  await import("./check-rotation-evidence-freshness.mjs");
} else if (contract === "AUTHENTICATED_OVERLAP") {
  if (values.some((value) => !value)) throw new Error("Initial-overlap activation bindings are incomplete.");
  execFileSync(process.execPath, [
    "scripts/security/production-initial-overlap-activation-contract.mjs",
    "--state-file", values[0], "--state-sha256", values[1], "--source-sha", values[2],
    "--rotation-id", values[3], "--deployment-sha", values[4], "--task-definition", values[5], "--image-digest", values[6],
  ], { cwd: process.cwd(), stdio: "inherit" });
} else throw new Error("Production activation rotation contract must be selected explicitly.");
