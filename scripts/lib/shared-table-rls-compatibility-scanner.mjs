import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { createRequire } from "node:module";

const require = createRequire(import.meta.url);
const TABLES = Object.freeze({
  organization: "Organization",
  licensee: "Licensee",
  user: "User",
  manufacturerLicenseeLink: "ManufacturerLicenseeLink",
});
const METHODS = new Set([
  "findUnique", "findUniqueOrThrow", "findFirst", "findFirstOrThrow", "findMany",
  "create", "createMany", "createManyAndReturn", "update", "updateMany", "updateManyAndReturn",
  "delete", "deleteMany", "upsert", "count", "aggregate", "groupBy",
]);
const RAW_METHODS = new Set(["$queryRaw", "$queryRawUnsafe", "$executeRaw", "$executeRawUnsafe"]);
const SOURCE_ROOTS = Object.freeze(["backend/src", "backend/scripts", "backend/tests", "scripts"]);
const SOURCE_FILES = Object.freeze([
  "backend/prisma/seed.ts",
]);
const EXCLUDED_DIRECTORIES = new Set(["dist", "node_modules", ".terraform", "coverage"]);

const operationFor = (method) => {
  if (method === "upsert") return "UPSERT";
  if (method === "count") return "COUNT";
  if (method.startsWith("create")) return "INSERT";
  if (method.startsWith("update")) return "UPDATE";
  if (method.startsWith("delete")) return "DELETE";
  return "SELECT";
};

const listFiles = (repoRoot) => {
  const files = [];
  const walk = (directory) => {
    for (const entry of fs.readdirSync(directory, { withFileTypes: true })) {
      if (entry.isDirectory() && EXCLUDED_DIRECTORIES.has(entry.name)) continue;
      const entryPath = path.join(directory, entry.name);
      if (entry.isDirectory()) walk(entryPath);
      else if (/\.(?:[cm]?js|ts)$/.test(entry.name)) files.push(entryPath);
    }
  };
  for (const root of SOURCE_ROOTS) walk(path.join(repoRoot, root));
  for (const file of SOURCE_FILES) files.push(path.join(repoRoot, file));
  return [...new Set(files)].sort();
};

const propertyName = (ts, node) => ts.isPropertyAccessExpression(node) ? node.name.text : null;
const containingFunction = (ts, node) => {
  for (let current = node.parent; current; current = current.parent) {
    if (ts.isFunctionDeclaration(current) && current.name) return current.name.text;
    if ((ts.isArrowFunction(current) || ts.isFunctionExpression(current)) && ts.isVariableDeclaration(current.parent)) {
      return current.parent.name.getText();
    }
    if ((ts.isArrowFunction(current) || ts.isFunctionExpression(current)) && ts.isPropertyAssignment(current.parent)) {
      return current.parent.name.getText();
    }
    if (ts.isMethodDeclaration(current) && current.name) return current.name.getText();
  }
  return "module";
};
const hasRlsContextAncestor = (ts, node) => {
  for (let current = node.parent; current; current = current.parent) {
    if (!ts.isCallExpression(current)) continue;
    const name = propertyName(ts, current.expression) || current.expression.getText();
    if (["withRlsPrototypeTransaction", "withStagingRlsBatchReadContext"].includes(name)) return true;
  }
  return false;
};
const rawText = (ts, call) => {
  if (ts.isTaggedTemplateExpression(call.parent)) return call.parent.template.getText();
  if (ts.isCallExpression(call.parent)) return call.parent.arguments.map((argument) => argument.getText()).join(" ");
  return "";
};
const stableId = (locator) => `shared-${crypto.createHash("sha256").update(locator).digest("hex").slice(0, 16)}`;

export const scanSharedTableAccesses = (repoRoot) => {
  const ts = require(path.join(repoRoot, "backend/node_modules/typescript"));
  const operations = [];
  for (const absolutePath of listFiles(repoRoot)) {
    const sourceFile = path.relative(repoRoot, absolutePath).split(path.sep).join("/");
    const source = fs.readFileSync(absolutePath, "utf8");
    const ast = ts.createSourceFile(sourceFile, source, ts.ScriptTarget.Latest, true);
    const record = (node, table, operation, method, client, evidenceText) => {
      const line = ast.getLineAndCharacterOfPosition(node.getStart(ast)).line + 1;
      const locator = `${sourceFile}:${line}:${table}:${operation}:${method}`;
      operations.push({
        id: stableId(locator), sourceFile, line, table, operation, method, client,
        serviceFunction: containingFunction(ts, node),
        syntacticRlsContext: hasRlsContextAncestor(ts, node) ? "transaction-local" : "none",
        evidenceText: evidenceText.replace(/\s+/g, " ").trim().slice(0, 500),
      });
    };
    const visit = (node) => {
      if (ts.isTaggedTemplateExpression(node) && ts.isPropertyAccessExpression(node.tag) && RAW_METHODS.has(node.tag.name.text)) {
        const text = node.template.getText();
        for (const table of Object.values(TABLES)) {
          if (new RegExp(`(?:public\\.)?["']${table}["']`, "i").test(text)) {
            record(node, table, "RAW_SQL", node.tag.name.text, node.tag.expression.getText(), text);
          }
        }
      }
      if (ts.isCallExpression(node) && ts.isPropertyAccessExpression(node.expression)) {
        const method = node.expression.name.text;
        const delegate = node.expression.expression;
        if (METHODS.has(method) && ts.isPropertyAccessExpression(delegate) && TABLES[delegate.name.text]) {
          record(node, TABLES[delegate.name.text], operationFor(method), method, delegate.expression.getText(), node.getText(ast));
        }
        if (RAW_METHODS.has(method)) {
          const text = rawText(ts, node.expression);
          for (const table of Object.values(TABLES)) {
            if (new RegExp(`(?:public\\.)?["']${table}["']`, "i").test(text)) {
              record(node, table, "RAW_SQL", method, node.expression.expression.getText(), text);
            }
          }
        }
      }
      ts.forEachChild(node, visit);
    };
    visit(ast);
  }
  return operations.sort((a, b) => a.sourceFile.localeCompare(b.sourceFile) || a.line - b.line || a.table.localeCompare(b.table));
};

export const scannerScope = Object.freeze({ sourceRoots: SOURCE_ROOTS, sourceFiles: SOURCE_FILES });
export const sharedTables = Object.freeze(Object.values(TABLES));
