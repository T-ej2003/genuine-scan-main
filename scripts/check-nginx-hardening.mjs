import { readFileSync } from "node:fs";
import path from "node:path";

const repoRoot = process.cwd();
const nginxFiles = ["nginx.conf", "nginx.https.conf"].map((file) => path.join(repoRoot, file));
const ecsNginxFile = path.join(repoRoot, "nginx.ecs-frontend.conf");

const requiredPatterns = [
  { name: "limit_conn_zone", pattern: /limit_conn_zone\s+\$binary_remote_addr/i },
  { name: "verify rate limit zone", pattern: /limit_req_zone\s+\$binary_remote_addr\s+zone=api_verify_ip/i },
  { name: "scan rate limit zone", pattern: /limit_req_zone\s+\$binary_remote_addr\s+zone=api_scan_ip/i },
  { name: "incidents rate limit zone", pattern: /limit_req_zone\s+\$binary_remote_addr\s+zone=api_incidents_ip/i },
  { name: "verify location", pattern: /location\s+~\s+\^\/api\/verify/i },
  { name: "scan location", pattern: /location\s+~\s+\^\/api\/scan/i },
  { name: "incidents location", pattern: /location\s+~\s+\^\/api\/incidents/i },
  { name: "runtime backend upstream", pattern: /set\s+\$backend_upstream\s+"__BACKEND_UPSTREAM__"/i },
  { name: "runtime DNS resolver", pattern: /resolver\s+__NGINX_RESOLVER__\s+valid=30s\s+ipv6=off/i },
  { name: "runtime proxy pass", pattern: /proxy_pass\s+\$backend_upstream/i },
  { name: "forwarded host header", pattern: /proxy_set_header\s+X-Forwarded-Host\s+\$host/i },
  { name: "external scheme map", pattern: /map\s+\$http_x_forwarded_proto\s+\$external_scheme\s*\{[\s\S]*~\*\^https\$\s+https;[\s\S]*\}/i },
  { name: "forwarded proto header preserves external scheme", pattern: /proxy_set_header\s+X-Forwarded-Proto\s+\$external_scheme/i },
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

  if (/\$scheme:\/\/www\.mscqr\.com/i.test(contents) || /return\s+301\s+http:\/\/www\.mscqr\.com/i.test(contents)) {
    failures.push(`${relative}: apex canonical redirects must not downgrade HTTPS traffic behind ALB TLS termination`);
  }
  if (!/map\s+"\$host:\$external_scheme"\s+\$redirect_www_http_to_https\s*\{[\s\S]*"www\.mscqr\.com:http"\s+1;[\s\S]*\}/i.test(contents)) {
    failures.push(`${relative}: www HTTP redirects must be gated by Host plus X-Forwarded-Proto-aware external scheme`);
  }
  if (!/if\s*\(\$redirect_www_http_to_https\)\s*\{[\s\S]*return\s+301\s+https:\/\/www\.mscqr\.com\$request_uri;[\s\S]*\}/i.test(contents)) {
    failures.push(`${relative}: www HTTP redirect must not catch ALB-forwarded HTTPS requests`);
  }
  if (/Report-To[\s\S]*http:\/\/www\.mscqr\.com/i.test(contents)) {
    failures.push(`${relative}: Report-To endpoint must stay HTTPS canonical`);
  }
  if (/proxy_pass\s+http:\/\/backend:4000/i.test(contents)) {
    failures.push(`${relative}: proxy_pass must use runtime BACKEND_UPSTREAM, not hardcoded backend:4000`);
  }
  if (!/location\s+~\s+\^\/api\/health\/\?\(\.\*\)\$[\s\S]*rewrite\s+\^\/api\/health\/\?\(\.\*\)\$\s+\/health\/\$1\s+break;[\s\S]*proxy_pass\s+\$backend_upstream/i.test(contents)) {
    failures.push(`${relative}: /api/health/* must rewrite to backend /health/* through runtime upstream`);
  }
}

const httpConfig = readFileSync(path.join(repoRoot, "nginx.conf"), "utf8");
if (!/server_name\s+mscqr\.com;[\s\S]*return\s+301\s+https:\/\/www\.mscqr\.com\$request_uri/i.test(httpConfig)) {
  failures.push("nginx.conf: apex redirect must canonicalize directly to https://www.mscqr.com/");
}

const httpsConfig = readFileSync(path.join(repoRoot, "nginx.https.conf"), "utf8");
if (/server_name\s+mscqr\.com\s+www\.mscqr\.com\s+_/i.test(httpsConfig)) {
  failures.push("nginx.https.conf: redirect-only HTTP server must not claim www/_ behind ALB TLS termination");
}
if (!/listen\s+80\s+default_server;[\s\S]*listen\s+443\s+ssl;[\s\S]*server_name\s+www\.mscqr\.com\s+_/i.test(httpsConfig)) {
  failures.push("nginx.https.conf: canonical www app server must serve ALB-forwarded HTTPS on port 80 and direct TLS on port 443");
}

const ecsConfig = readFileSync(ecsNginxFile, "utf8");
for (const check of [
  { name: "runtime backend upstream", pattern: /set\s+\$backend_upstream\s+"__BACKEND_UPSTREAM__"/i },
  { name: "runtime DNS resolver", pattern: /resolver\s+__NGINX_RESOLVER__\s+valid=30s\s+ipv6=off/i },
  { name: "runtime proxy pass", pattern: /proxy_pass\s+\$backend_upstream/i },
  { name: "direct healthz", pattern: /location\s+=\s+\/healthz[\s\S]*return\s+200\s+"ok\\n"/i },
]) {
  if (!check.pattern.test(ecsConfig)) failures.push(`nginx.ecs-frontend.conf: missing ${check.name}`);
}
if (/proxy_pass\s+http:\/\/backend:4000/i.test(ecsConfig)) {
  failures.push("nginx.ecs-frontend.conf: proxy_pass must use runtime BACKEND_UPSTREAM, not hardcoded backend:4000");
}
if (!/location\s+~\s+\^\/api\/health\/\?\(\.\*\)\$[\s\S]*rewrite\s+\^\/api\/health\/\?\(\.\*\)\$\s+\/health\/\$1\s+break;[\s\S]*proxy_pass\s+\$backend_upstream/i.test(ecsConfig)) {
  failures.push("nginx.ecs-frontend.conf: /api/health/* must rewrite to backend /health/* through runtime upstream");
}

if (failures.length > 0) {
  console.error("Nginx hardening check failed:");
  for (const failure of failures) {
    console.error(`- ${failure}`);
  }
  process.exit(1);
}

console.log("Nginx hardening check passed.");
