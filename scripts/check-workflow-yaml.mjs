import fs from "node:fs";
import path from "node:path";
import yaml from "js-yaml";

const root = path.resolve(".github/workflows");
const files = fs.readdirSync(root).filter((file) => /\.ya?ml$/.test(file)).sort();
for (const file of files) {
  const filePath = path.join(root, file);
  try {
    yaml.load(fs.readFileSync(filePath, "utf8"));
  } catch (error) {
    throw new Error(`${path.relative(process.cwd(), filePath)} is invalid YAML: ${error.message}`);
  }
}
console.log(`Workflow YAML valid: ${files.length} file(s).`);
