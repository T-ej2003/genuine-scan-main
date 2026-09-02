import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import test from "node:test";
import yaml from "js-yaml";

test("all GitHub workflow YAML is parseable before CI", () => {
  const directory = path.resolve(".github/workflows");
  for (const file of fs.readdirSync(directory).filter((name) => /\.ya?ml$/.test(name))) assert.doesNotThrow(() => yaml.load(fs.readFileSync(path.join(directory, file), "utf8")), file);
});
