#!/usr/bin/env node
import fs from "node:fs";
import path from "node:path";
import { execFileSync } from "node:child_process";

const args = process.argv.slice(2);

const readArgValue = (flag) => {
  const index = args.indexOf(flag);
  if (index === -1) return "";
  return String(args[index + 1] || "").trim();
};

const hasArg = (flag) => args.includes(flag);

const installerPathInput = readArgValue("--file");
const expectSigned = hasArg("--expect-signed");
const expectedPublisherName = readArgValue("--publisher-name");

if (!installerPathInput) {
  throw new Error("Usage: node verify-windows-installer.mjs --file <path-to-msi-or-exe> [--expect-signed] [--publisher-name <name>]");
}

const installerPath = path.isAbsolute(installerPathInput)
  ? installerPathInput
  : path.resolve(process.cwd(), installerPathInput);

if (!fs.existsSync(installerPath)) {
  throw new Error(`Installer file does not exist: ${installerPath}`);
}

const ext = path.extname(installerPath).toLowerCase();
if (ext !== ".exe" && ext !== ".msi") {
  throw new Error("Windows installer verification expects a .exe or .msi file.");
}

const fileSize = fs.statSync(installerPath).size;
if (fileSize <= 0) {
  throw new Error("Installer file is empty.");
}

console.log(`Verified file exists: ${installerPath}`);
console.log(`Size: ${fileSize} bytes`);

if (!expectSigned) {
  console.log("Signature verification skipped. Use --expect-signed on a Windows machine after signing.");
  process.exit(0);
}

if (process.platform !== "win32") {
  throw new Error("Authenticode signature verification requires a Windows machine.");
}

const signatureJson = execFileSync(
  "powershell.exe",
  [
    "-NoProfile",
    "-Command",
    `Get-AuthenticodeSignature -FilePath '${installerPath.replace(/'/g, "''")}' | Select-Object Status,StatusMessage,@{Name='Subject';Expression={$_.SignerCertificate.Subject}},@{Name='Timestamp';Expression={$_.TimeStamperCertificate.NotBefore}} | ConvertTo-Json -Compress`,
  ],
  { encoding: "utf8" },
).trim();

const signature = JSON.parse(signatureJson);
if (!signature || String(signature.Status || "").toLowerCase() !== "valid") {
  throw new Error(`Windows signature is not valid: ${signature?.StatusMessage || signature?.Status || "unknown status"}`);
}

if (expectedPublisherName && !String(signature.Subject || "").includes(expectedPublisherName)) {
  throw new Error(`Expected publisher "${expectedPublisherName}" was not found in signature subject "${signature.Subject || ""}".`);
}

if (!signature.Timestamp) {
  throw new Error("Signed installer is missing a timestamp.");
}

console.log(`Signature status: ${signature.Status}`);
console.log(`Publisher subject: ${signature.Subject}`);
console.log(`Timestamp: ${signature.Timestamp}`);
