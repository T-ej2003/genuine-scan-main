import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { createHash } from "node:crypto";
import JSZip from "jszip";
import { terraformExecution } from "./component-terraform-isolation.mjs";

const root = fileURLToPath(new URL("../../", import.meta.url));
const stack = "infra/aws/terraform/production-component-deployment-state";
export const terraformCliConfiguration = 'provider_installation {\n  filesystem_mirror {\n    path = "/inputs/providers"\n    include = ["registry.terraform.io/hashicorp/aws"]\n  }\n}\ndisable_checkpoint = true\n';
const sha = value => createHash("sha256").update(value).digest("hex");

export async function prepareIsolatedTerraformInputs() {
  assert.equal(arguments.length, 0, "Input overrides are forbidden");
  const architecture = { x64: "amd64", arm64: "arm64" }[process.arch]; assert(architecture);
  const expected = terraformExecution.archives[architecture];
  const sourceNames = ["main.tf", "providers.tf", "versions.tf", ".terraform.lock.hcl"];
  const present = fs.readdirSync(path.join(root, stack)).filter(name => /\.tf(?:\.json)?$|\.tfvars(?:\.json)?$/.test(name)).sort();
  assert.deepEqual(present, sourceNames.filter(name => name.endsWith(".tf")).sort(), "Unexpected Terraform source input");
  const source = Object.fromEntries(sourceNames.map(name => {
    const file = path.join(root, stack, name); assert(fs.lstatSync(file).isFile());
    return [`root/${name}`, fs.readFileSync(file)];
  }));
  const lock = source["root/.terraform.lock.hcl"].toString();
  assert(lock.includes(`version     = "${terraformExecution.providerVersion}"`) && lock.includes(`zh:${expected.provider}`), "Committed provider lock does not bind the reviewed platform archive");
  assert(source["root/versions.tf"].toString().includes(`required_version = "= ${terraformExecution.terraformVersion}"`));
  assert(source["root/versions.tf"].toString().includes(`version = "= ${terraformExecution.providerVersion}"`));
  const runnerSources = [["agent.mjs", "component-terraform-agent.mjs"], ["component-terraform-isolation.mjs", "component-terraform-isolation.mjs"], ["component-terraform-network.mjs", "component-terraform-network.mjs"]];
  for (const [name, sourceName] of runnerSources) {
    const file = path.join(root, "scripts/aws", sourceName); assert(fs.lstatSync(file).isFile()); source[name] = fs.readFileSync(file);
  }
  const download = async (name, version, checksum) => {
    const response = await fetch(`https://releases.hashicorp.com/${name}/${version}/${name}_${version}_linux_${architecture}.zip`, { redirect: "error", signal: AbortSignal.timeout(300000) });
    assert(response.ok);
    const length = Number(response.headers.get("content-length")); assert(length > 0 && length < 256 * 1024 * 1024);
    const bytes = Buffer.from(await response.arrayBuffer()); assert.equal(bytes.length, length); assert.equal(sha(bytes), checksum, "Executable download differs from source-pinned checksum");
    return bytes;
  };
  const terraform = await download("terraform", terraformExecution.terraformVersion, expected.terraform);
  const zip = await JSZip.loadAsync(terraform, { checkCRC32: true });
  assert.deepEqual(Object.keys(zip.files).sort(), ["LICENSE.txt", "terraform"]);
  assert(!zip.files.terraform.dir && !zip.files.terraform.unsafeOriginalName?.includes("/"));
  source["terraform"] = await zip.file("terraform").async("nodebuffer");
  const providerName = `providers/registry.terraform.io/hashicorp/aws/terraform-provider-aws_${terraformExecution.providerVersion}_linux_${architecture}.zip`;
  source[providerName] = await download("terraform-provider-aws", terraformExecution.providerVersion, expected.provider);
  source["terraform.rc"] = Buffer.from(terraformCliConfiguration);
  // Recheck source after all downloads. Production composition additionally
  // authenticates clean protected main before and after this preparation.
  for (const name of sourceNames) assert.equal(sha(fs.readFileSync(path.join(root, stack, name))), sha(source[`root/${name}`]), "Source moved during executable preparation");
  for (const [name, sourceName] of runnerSources) {
    assert.equal(sha(fs.readFileSync(path.join(root, "scripts/aws", sourceName))), sha(source[name]), "Runner source moved during executable preparation");
  }
  const directory = fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), "mscqr-component-terraform-inputs-")));
  fs.chmodSync(directory, 0o700);
  try {
    for (const [name, bytes] of Object.entries(source)) {
      const target = path.join(directory, name); fs.mkdirSync(path.dirname(target), { recursive: true, mode: 0o700 });
      fs.writeFileSync(target, bytes, { mode: name === "terraform" ? 0o555 : 0o444, flag: "wx" });
    }
    const manifest = { schemaVersion: 1, architecture, terraformVersion: terraformExecution.terraformVersion, providerVersion: terraformExecution.providerVersion,
      image: terraformExecution.image, files: Object.fromEntries(Object.entries(source).map(([name, bytes]) => [name, sha(bytes)])) };
    const bytes = Buffer.from(JSON.stringify(manifest));
    fs.writeFileSync(path.join(directory, "manifest.json"), bytes, { mode: 0o444, flag: "wx" });
    return { directory, manifest, manifestSha256: sha(bytes), dispose: () => fs.rmSync(directory, { recursive: true }) };
  } catch (error) { fs.rmSync(directory, { recursive: true }); throw error; }
}
