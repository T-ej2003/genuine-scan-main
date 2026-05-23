import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

export const backendRoot = path.resolve(__dirname, "../..");

export const readConnectorSourceVersion = (root = backendRoot) => {
  const sourcePath = path.join(root, "src", "local-print-agent", "version.ts");
  const source = fs.readFileSync(sourcePath, "utf8");
  const match = source.match(/export\s+const\s+LOCAL_PRINT_AGENT_SOURCE_VERSION\s*=\s*"([^"]+)"/);
  if (!match) {
    throw new Error(`Could not read LOCAL_PRINT_AGENT_SOURCE_VERSION from ${sourcePath}`);
  }
  return match[1];
};

export const assertConnectorVersionMatchesSource = (version, root = backendRoot) => {
  const sourceVersion = readConnectorSourceVersion(root);
  if (String(version || "").trim() !== sourceVersion) {
    throw new Error(
      `Refusing to publish connector version ${version || "(empty)"}; source connector buildVersion is ${sourceVersion}.`
    );
  }
  return sourceVersion;
};
