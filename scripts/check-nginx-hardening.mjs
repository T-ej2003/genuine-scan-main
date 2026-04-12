import { readFileSync } from "node:fs";
import path from "node:path";

const repoRoot = process.cwd();
const nginxFiles = ["nginx.conf", "nginx.https.conf"].map((file) => path.join(repoRoot, file));

const requiredPatterns = [
  { name: "limit_conn_zone", pattern: /limit_conn_zone\s+\$binary_remote_addr/i },
  { name: "verify rate limit zone", pattern: /limit_req_zone\s+\$binary_remote_addr\s+zone=api_verify_ip/i },
  { name: "scan rate limit zone", pattern: /limit_req_zone\s+\$binary_remote_addr\s+zone=api_scan_ip/i },
  { name: "incidents rate limit zone", pattern: /limit_req_zone\s+\$binary_remote_addr\s+zone=api_incidents_ip/i },
  { name: "verify location", pattern: /location\s+~\s+\^\/api\/verify/i },
  { name: "scan location", pattern: /location\s+~\s+\^\/api\/scan/i },
  { name: "incidents location", pattern: /location\s+~\s+\^\/api\/incidents/i },
  { name: "forwarded host header", pattern: /proxy_set_header\s+X-Forwarded-Host\s+\$host/i },
];

const failures = [];

for (const filePath of nginxFiles) {
  const relative = path.relative(repoRoot, filePath);
  const contents = readFileSync(filePath, "utf8");

  for (const check of requiredPatterns) {
    if (!check.pattern.test(contents)) {
      failures.push(`${relative}: missing ${check.name}`);
    }
  }

  const cspLines = contents
    .split("\n")
    .map((line) => line.trim())
    .filter((line) => line.toLowerCase().includes("content-security-policy"));

  const scriptUnsafeInline = cspLines.some((line) => /script-src[^;]*'unsafe-inline'/i.test(line));
  if (scriptUnsafeInline) {
    failures.push(`${relative}: script-src still allows 'unsafe-inline'`);
  }
  const styleUnsafeInline = cspLines.some(
    (line) => !/content-security-policy-report-only/i.test(line) && /style-src[^;]*'unsafe-inline'/i.test(line)
  );
  if (styleUnsafeInline) {
    failures.push(`${relative}: style-src still allows 'unsafe-inline'`);
  }

  const strictReportOnlyStyle = cspLines.some((line) =>
    /content-security-policy-report-only/i.test(line) && /style-src\s+'self'(?=[;\"])/i.test(line)
  );
  if (!strictReportOnlyStyle) {
    failures.push(`${relative}: report-only CSP must include strict style-src 'self'`);
  }
}

if (failures.length > 0) {
  console.error("Nginx hardening check failed:");
  for (const failure of failures) {
    console.error(`- ${failure}`);
  }
  process.exit(1);
}

console.log("Nginx hardening check passed.");
