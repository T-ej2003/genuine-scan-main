import assert from "node:assert/strict";
import { assertPinnedImageInputs, verifyApprovedImage } from "./lib/container-image-identity.mjs";

const mode = process.argv[2];
assert.ok(process.argv.length <= 3 && [undefined, "--production", "--review-upstream"].includes(mode), "Unsupported image provenance mode");
const images = assertPinnedImageInputs();
for (const [name, image] of Object.entries(images)) {
  if (mode === "--production" && !["nginx", "node"].includes(name)) continue;
  await verifyApprovedImage(image);
  if (mode === "--review-upstream") await verifyApprovedImage(image, { upstream: true });
  console.log(`${name}: approved amd64/arm64 ${image.digest}`);
}
