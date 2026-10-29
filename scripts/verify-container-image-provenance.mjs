import assert from "node:assert/strict";
import { assertPinnedImageInputs, assertPinnedDockerfiles, verifyApprovedImage } from "./lib/container-image-identity.mjs";

const mode = process.argv[2];
assert.ok(process.argv.length <= 3 && [undefined, "--production", "--production-mirror", "--review-upstream", "--ci"].includes(mode), "Unsupported image provenance mode");
const images = mode === "--production-mirror" ? assertPinnedDockerfiles(process.cwd()) : assertPinnedImageInputs();
for (const [name, image] of Object.entries(images)) {
  if (["--production", "--production-mirror"].includes(mode) && !["nginx", "node"].includes(name)) continue;
  await verifyApprovedImage(image, { ci: ["--ci", "--production-mirror"].includes(mode) });
  if (mode === "--review-upstream") await verifyApprovedImage(image, { upstream: true });
  console.log(`${name}: approved amd64/arm64 ${image.digest}`);
}
