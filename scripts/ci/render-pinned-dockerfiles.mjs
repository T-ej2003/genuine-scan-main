import assert from "node:assert/strict";
import { readFileSync, writeFileSync } from "node:fs";
import path from "node:path";
import { assertPinnedDockerfiles, ciImageReference } from "../lib/container-image-identity.mjs";

const output = process.argv[2];
assert.ok(process.argv.length === 3 && path.isAbsolute(output), "Expected absolute CI output directory");
const images = assertPinnedDockerfiles(process.cwd());
for (const [source, target] of [["Dockerfile", "frontend.Dockerfile"], ["Dockerfile.ecs-frontend", "ecs-frontend.Dockerfile"], ["backend/Dockerfile", "backend.Dockerfile"]]) {
  let content = readFileSync(source, "utf8");
  for (const key of ["node", "nginx"]) content = content.replaceAll(images[key].reference, ciImageReference(images[key]));
  assert.doesNotMatch(content, /public\.ecr\.aws\/docker\/library\//);
  writeFileSync(path.join(output, target), content, { mode: 0o600 });
}
