import { readdirSync, readFileSync, statSync } from "node:fs";
import path from "node:path";

const repoRoot = process.cwd();

const walk = (dir) => {
  const entries = readdirSync(dir, { withFileTypes: true });
  const files = [];

  for (const entry of entries) {
    const fullPath = path.join(dir, entry.name);
    if (entry.isDirectory()) {
      if (["node_modules", "dist", ".git", "coverage"].includes(entry.name)) continue;
      files.push(...walk(fullPath));
      continue;
    }

    if (!entry.isFile()) continue;
    files.push(fullPath);
  }

  return files;
};

const scanTargets = [
  path.join(repoRoot, "backend", "src"),
  path.join(repoRoot, "src"),
];

const rules = [
  {
    name: "Prisma unsafe raw SQL",
    matcher: /\.(ts|tsx|js|mjs|cjs)$/,
    allow: () => false,
    patterns: [/\bqueryRawUnsafe\s*\(/g, /\bexecuteRawUnsafe\s*\(/g],
    message: "Unsafe Prisma raw SQL is forbidden. Use parameterized Prisma APIs instead.",
  },
  {
    name: "Backend child_process outside local-print-agent",
    matcher: /\.(ts|js|mjs|cjs)$/,
    allow: (filePath) => filePath.includes(`${path.sep}backend${path.sep}src${path.sep}local-print-agent${path.sep}`),
    patterns: [/\bfrom\s+["']child_process["']/g, /\brequire\(["']child_process["']\)/g],
    message: "Server-side child_process usage is only allowed inside backend/src/local-print-agent.",
  },
];

const findings = [];

for (const target of scanTargets) {
  if (!statSync(target).isDirectory()) continue;

  for (const filePath of walk(target)) {
    for (const rule of rules) {
      if (!rule.matcher.test(filePath)) continue;
      if (rule.allow(filePath)) continue;

      const contents = readFileSync(filePath, "utf8");
      for (const pattern of rule.patterns) {
        pattern.lastIndex = 0;
        const match = pattern.exec(contents);
        if (!match) continue;

        const line = contents.slice(0, match.index).split("\n").length;
        findings.push({
          filePath: path.relative(repoRoot, filePath),
          line,
          rule: rule.name,
          message: rule.message,
        });
      }
    }
  }
}

if (findings.length > 0) {
  console.error("Security guardrail check failed:");
  for (const finding of findings) {
    console.error(`- ${finding.filePath}:${finding.line} [${finding.rule}] ${finding.message}`);
  }
  process.exit(1);
}

console.log("Security guardrail check passed.");
