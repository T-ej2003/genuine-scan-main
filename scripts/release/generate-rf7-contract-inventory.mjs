#!/usr/bin/env node
import fs from "node:fs";
import path from "node:path";
import ts from "typescript";
import { scanProductionAccess } from "../rls/lib/program-inventory.mjs";
import { validateNamedSqlFunctionContracts } from "../rls/lib/named-sql-function-contracts.mjs";

const root = path.resolve(new URL("../..", import.meta.url).pathname);
const outputPath = path.join(root, "documents/security/rls-program/release-fix-7-contract-inventory.json");
const routeMethods = new Set(["get", "post", "put", "patch", "delete"]);
const forceRlsTables = new Set(
  JSON.parse(fs.readFileSync(path.join(root, "documents/security/rls-program/generated/force-rls-report.json"), "utf8")).tables
);
const protectedTableIds = new Set(
  JSON.parse(fs.readFileSync(path.join(root, "documents/security/rls-program/tables.json"), "utf8"))
    .tables.filter((table) => forceRlsTables.has(table.physicalTable))
    .map((table) => table.id)
);
const capabilities = validateNamedSqlFunctionContracts();
const workflows = JSON.parse(
  fs.readFileSync(path.join(root, "documents/security/rls-program/workflows.json"), "utf8")
).workflows;
const scopeAllowlist = JSON.parse(
  fs.readFileSync(path.join(root, "scripts/security-scope-allowlist.json"), "utf8")
).allowedFindings;

const rel = (file) => path.relative(root, file).replaceAll("\\", "/");
const walk = (dir) => fs.readdirSync(dir, { withFileTypes: true }).flatMap((entry) => {
  const file = path.join(dir, entry.name);
  if (entry.isDirectory()) return ["node_modules", "dist", ".prisma"].includes(entry.name) ? [] : walk(file);
  return entry.isFile() && /\.(?:ts|tsx)$/.test(entry.name) ? [file] : [];
});
const sourceFile = (file) => ts.createSourceFile(file, fs.readFileSync(file, "utf8"), ts.ScriptTarget.Latest, true);
const lineOf = (node, source) => source.getLineAndCharacterOfPosition(node.getStart(source)).line + 1;
const textOf = (node, source) => node.getText(source).replace(/\s+/g, " ").slice(0, 240);
const functionNameOf = (node) => {
  for (let current = node.parent; current; current = current.parent) {
    if (ts.isFunctionDeclaration(current) && current.name) return current.name.text;
    if (ts.isVariableDeclaration(current) && ts.isIdentifier(current.name)) return current.name.text;
  }
  return null;
};
const backendFiles = walk(path.join(root, "backend/src"));
const backendConfigFile = ts.readConfigFile(path.join(root, "backend/tsconfig.json"), ts.sys.readFile);
const backendConfig = ts.parseJsonConfigFileContent(backendConfigFile.config, ts.sys, path.join(root, "backend"));
const backendProgram = ts.createProgram(backendFiles, backendConfig.options);
const backendChecker = backendProgram.getTypeChecker();
const declarationKey = (declaration) => {
  const source = declaration?.getSourceFile?.();
  const name =
    declaration && (
      (ts.isFunctionDeclaration(declaration) && declaration.name?.text) ||
      (ts.isVariableDeclaration(declaration) && ts.isIdentifier(declaration.name) && declaration.name.text) ||
      (ts.isMethodDeclaration(declaration) && declaration.name?.getText(source)) ||
      functionNameOf(declaration)
    );
  return source && name ? `${rel(source.fileName)}:${name}` : null;
};
const localDeclarationsFor = (node) => {
  let symbol = backendChecker.getSymbolAtLocation(node);
  if (!symbol) return [];
  if (symbol.flags & ts.SymbolFlags.Alias) {
    try { symbol = backendChecker.getAliasedSymbol(symbol); } catch { return []; }
  }
  return (symbol.declarations || []).filter((declaration) =>
    declaration.getSourceFile().fileName.includes(`${path.sep}backend${path.sep}src${path.sep}`)
  );
};
const reachableBackendFunctions = new Set();
const pendingBackendFunctions = [];
const queueDeclaration = (declaration) => {
  const key = declarationKey(declaration);
  if (!key || reachableBackendFunctions.has(key)) return;
  reachableBackendFunctions.add(key);
  pendingBackendFunctions.push(declaration);
};
const queueReferences = (node) => {
  if (ts.isCallExpression(node) || ts.isNewExpression(node)) {
    for (const declaration of localDeclarationsFor(node.expression)) queueDeclaration(declaration);
    for (const argument of node.arguments || []) {
      if (ts.isIdentifier(argument) || ts.isPropertyAccessExpression(argument)) {
        for (const declaration of localDeclarationsFor(argument)) queueDeclaration(declaration);
      }
    }
  }
  ts.forEachChild(node, queueReferences);
};
const queueRuntimeRootReferences = (node) => {
  if (
    ts.isFunctionDeclaration(node) ||
    ts.isFunctionExpression(node) ||
    ts.isArrowFunction(node) ||
    ts.isClassDeclaration(node) ||
    ts.isClassExpression(node)
  ) return;
  if (ts.isCallExpression(node) || ts.isNewExpression(node)) {
    for (const declaration of localDeclarationsFor(node.expression)) queueDeclaration(declaration);
    for (const argument of node.arguments || []) {
      if (ts.isIdentifier(argument) || ts.isPropertyAccessExpression(argument)) {
        for (const declaration of localDeclarationsFor(argument)) queueDeclaration(declaration);
      }
    }
  }
  ts.forEachChild(node, queueRuntimeRootReferences);
};
for (const source of backendProgram.getSourceFiles()) {
  const sourcePath = rel(source.fileName);
  const isRuntimeRoot =
    sourcePath.startsWith("backend/src/routes/") ||
    [
      "backend/src/index.ts",
      "backend/src/worker.ts",
      "backend/src/app.ts",
      "backend/src/local-print-agent/index.ts",
    ].includes(sourcePath);
  if (!isRuntimeRoot) continue;
  for (const statement of source.statements) {
    queueRuntimeRootReferences(statement);
  }
}
while (pendingBackendFunctions.length) queueReferences(pendingBackendFunctions.shift());
const literalPath = (node, source) => {
  if (ts.isStringLiteralLike(node)) return node.text;
  if (!ts.isTemplateExpression(node)) return null;
  let value = node.head.text;
  for (const span of node.templateSpans) {
    const expression = textOf(span.expression, source);
    if (expression === "BASE_URL") {
      value += span.literal.text;
      continue;
    }
    if (
      expression === "endpoint" ||
      expression === "url" ||
      expression === "query" ||
      expression.includes("params.toString()") ||
      span.literal.text.startsWith("?")
    ) {
      return value || null;
    }
    value += `:${expression.replace(/\W+/g, "_")}${span.literal.text}`;
  }
  return value;
};
const canonicalPath = (value) =>
  String(value || "")
    .split("?")[0]
    .replace(/\/+/g, "/")
    .replace(/\/$/, "") || "/";
const routePattern = (value) =>
  new RegExp(`^${canonicalPath(value).replace(/[.*+?^${}()|[\]\\]/g, "\\$&").replace(/:[A-Za-z0-9_]+/g, "[^/]+")}/?$`);

const mountPrefixes = new Map();
for (const file of walk(path.join(root, "backend/src/routes"))) {
  const source = sourceFile(file);
  const visit = (node) => {
    if (ts.isCallExpression(node) && ts.isPropertyAccessExpression(node.expression) && node.expression.name.text === "use") {
      const prefix = node.arguments[0] && literalPath(node.arguments[0], source);
      const mounted = node.arguments[1];
      if (prefix && mounted && ts.isCallExpression(mounted) && ts.isIdentifier(mounted.expression)) {
        mountPrefixes.set(mounted.expression.text, prefix);
      }
    }
    ts.forEachChild(node, visit);
  };
  visit(source);
}

const routes = [];
for (const file of walk(path.join(root, "backend/src/routes"))) {
  if (file.endsWith("publicRoutes.ts")) continue;
  const source = sourceFile(file);
  const visit = (node) => {
    if (
      ts.isCallExpression(node) &&
      ts.isPropertyAccessExpression(node.expression) &&
      routeMethods.has(node.expression.name.text) &&
      node.arguments[0]
    ) {
      const rawPath = literalPath(node.arguments[0], source);
      if (rawPath) {
        const owner = functionNameOf(node);
        const prefix = owner ? mountPrefixes.get(owner) || "" : "";
        const middleware = node.arguments.slice(1).map((argument) => textOf(argument, source));
        routes.push({
          method: node.expression.name.text.toUpperCase(),
          path: canonicalPath(`${prefix}${rawPath}`),
          source: `${rel(file)}:${lineOf(node, source)}`,
          middleware,
          handler: middleware.at(-1) || null,
        });
      }
    }
    ts.forEachChild(node, visit);
  };
  visit(source);
}

const frontendConsumers = [];
const dynamicNavigation = [];
for (const file of walk(path.join(root, "src"))) {
  if (file.includes(`${path.sep}test${path.sep}`)) continue;
  const source = sourceFile(file);
  const visit = (node) => {
    if (ts.isCallExpression(node)) {
      const callee = node.expression;
      const name = ts.isIdentifier(callee) ? callee.text : ts.isPropertyAccessExpression(callee) ? callee.name.text : null;
      if ((name === "request" || name === "fetch") && node.arguments[0]) {
        const endpoint = literalPath(node.arguments[0], source);
        let method = "GET";
        const options = node.arguments[1];
        if (options && ts.isObjectLiteralExpression(options)) {
          const property = options.properties.find(
            (item) => ts.isPropertyAssignment(item) && item.name.getText(source).replaceAll("\"", "") === "method"
          );
          if (property && ts.isPropertyAssignment(property) && ts.isStringLiteralLike(property.initializer)) {
            method = property.initializer.text.toUpperCase();
          }
        }
        frontendConsumers.push({
          method,
          path: endpoint ? canonicalPath(endpoint) : null,
          source: `${rel(file)}:${lineOf(node, source)}`,
          call: textOf(node, source),
          dynamic: !endpoint,
          runtimeOrigin: file.endsWith("internal-client-local-agent.ts") ? "loopback-print-agent" : "mscqr-backend",
        });
      }
      if (name === "navigate" && node.arguments[0] && !literalPath(node.arguments[0], source)) {
        dynamicNavigation.push({
          source: `${rel(file)}:${lineOf(node, source)}`,
          expression: textOf(node.arguments[0], source),
        });
      }
    }
    if (ts.isJsxAttribute(node) && node.name.text === "to" && node.initializer && ts.isJsxExpression(node.initializer)) {
      const expression = node.initializer.expression;
      if (expression && !literalPath(expression, source)) {
        dynamicNavigation.push({
          source: `${rel(file)}:${lineOf(node, source)}`,
          expression: textOf(expression, source),
        });
      }
    }
    ts.forEachChild(node, visit);
  };
  visit(source);
}

const routeKeys = new Set(routes.map((route) => `${route.method} ${route.path}`));
const missingFrontendRoutes = frontendConsumers.filter((consumer) => {
  if (
    consumer.runtimeOrigin !== "mscqr-backend" ||
    !consumer.path ||
    consumer.path.startsWith("http")
  ) return false;
  return !routes.some((route) => route.method === consumer.method && routePattern(route.path).test(consumer.path));
});
const canonicalAccessIds = new Set(
  workflows
    .filter((workflow) => workflow.contextBoundaryStatus === "implemented" && workflow.sameTransactionGuarantee === true)
    .flatMap((workflow) => workflow.supportingEvidence.map((evidence) => evidence.accessId))
);
const directProtectedAccesses = scanProductionAccess().accesses
  .filter((access) => access.production && protectedTableIds.has(access.tableId) && !String(access.method).startsWith("$function:"))
  .map((access) => {
    const model = access.prismaModel[0].toLowerCase() + access.prismaModel.slice(1);
    const legacyException = scopeAllowlist.find(
      (entry) =>
        entry.path === access.sourceFile &&
        entry.model === model &&
        (entry.methods || [entry.method]).includes(access.method)
    );
    const nonRuntime =
      access.sourceFile.startsWith("scripts/")
          ? "administrative-tooling"
          : access.function && !reachableBackendFunctions.has(`${access.sourceFile}:${access.function}`)
            ? "not-statically-reachable"
          : null;
    return {
      id: access.id,
      source: `${access.sourceFile}:${access.line}`,
      function: access.function,
      tableId: access.tableId,
      command: access.command,
      method: access.method,
      registration: access.registrationEvidence,
      authorityStatus: nonRuntime || (canonicalAccessIds.has(access.id)
        ? "reviewed-transaction-boundary"
        : legacyException
          ? "legacy-exception"
          : "uncontrolled"),
    };
  });
const accessStatusCounts = directProtectedAccesses.reduce((counts, access) => {
  counts[access.authorityStatus] = (counts[access.authorityStatus] || 0) + 1;
  return counts;
}, {});
const reachableDirectProtectedAccesses = directProtectedAccesses.filter((access) =>
  !["not-statically-reachable", "administrative-tooling"].includes(access.authorityStatus)
);

const result = {
  schemaVersion: 1,
  generatedFrom: [
    "scripts/rls/lib/named-sql-function-contracts.mjs",
    "documents/security/rls-program/generated/force-rls-report.json",
    "backend/src/routes/**/*.ts",
    "src/**/*.ts{x}",
    "scripts/rls/lib/program-inventory.mjs",
  ],
  summary: {
    reviewedCapabilities: capabilities.length,
    runtimeExecutableCapabilities: capabilities.filter((item) => item.security?.runtimeExecuteGrantees?.length).length,
    routes: routes.length,
    uniqueRoutes: routeKeys.size,
    frontendConsumers: frontendConsumers.length,
    dynamicFrontendConsumers: frontendConsumers.filter((item) => item.dynamic).length,
    missingFrontendRoutes: missingFrontendRoutes.length,
    dynamicNavigationSites: dynamicNavigation.length,
    directProtectedAccessReferences: directProtectedAccesses.length,
    reachableDirectProtectedAccesses: reachableDirectProtectedAccesses.length,
    directAccessAuthorityStatus: accessStatusCounts,
  },
  databaseCapabilities: capabilities.map((item) => ({
    functionName: `${item.schema}.${item.name}`,
    signature: item.signature,
    returnType: item.returnType,
    owner: item.security?.ownerIdentity || null,
    runtimeGrantees: item.security?.runtimeExecuteGrantees || [],
    inputAuthority: item.inputAuthority,
    outputColumns: item.outputColumns,
    context: item.context,
    tables: item.tableCommands || [],
    workflows: item.canonicalWorkflowIds || [],
    repositoryCallers: item.repositoryCallers || [],
    idempotencyAndTransactionGuarantees: item.invariant || item.context,
    auditAndOutboxEffects: (item.tableCommands || []).filter(([table]) =>
      /Audit|Outbox|Event/.test(table)
    ),
    denialEvidence: item.disposableProbes || [],
    rollback: item.security?.rollbackDefinition || null,
  })),
  backendAuthority: {
    reachableFunctions: [...reachableBackendFunctions].sort(),
  },
  backendRoutes: routes.sort((a, b) => `${a.path}:${a.method}:${a.source}`.localeCompare(`${b.path}:${b.method}:${b.source}`)),
  frontendConsumers: frontendConsumers.sort((a, b) => a.source.localeCompare(b.source)),
  drift: {
    missingFrontendRoutes,
    dynamicNavigation,
    directProtectedAccesses,
    directAccessAuthorityStatus: accessStatusCounts,
  },
};

fs.mkdirSync(path.dirname(outputPath), { recursive: true });
fs.writeFileSync(outputPath, `${JSON.stringify(result, null, 2)}\n`);
console.log(JSON.stringify(result.summary, null, 2));
