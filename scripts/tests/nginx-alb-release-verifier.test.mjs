import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import path from "node:path";
import test from "node:test";

const repoRoot = path.resolve(import.meta.dirname, "../..");
const readRepoFile = (filePath) => readFileSync(path.join(repoRoot, filePath), "utf8");

test("nginx redirects public HTTP www without catching ALB-forwarded HTTPS", () => {
  for (const filePath of ["nginx.conf", "nginx.https.conf"]) {
    const contents = readRepoFile(filePath);

    assert.match(
      contents,
      /map\s+"\$host:\$external_scheme"\s+\$redirect_www_http_to_https\s*\{[\s\S]*"www\.mscqr\.com:http"\s+1;[\s\S]*\}/,
      `${filePath} must key the www redirect on host plus external scheme`
    );
    assert.match(
      contents,
      /if\s*\(\$redirect_www_http_to_https\)\s*\{[\s\S]*return\s+301\s+https:\/\/www\.mscqr\.com\$request_uri;[\s\S]*\}/,
      `${filePath} must redirect only public HTTP www traffic`
    );
    assert.doesNotMatch(
      contents,
      /server_name\s+mscqr\.com\s+www\.mscqr\.com\s+_/,
      `${filePath} must not put www/_ in a redirect-only server`
    );
  }
});

test("nginx HTTPS template serves ALB-forwarded HTTPS on port 80", () => {
  const contents = readRepoFile("nginx.https.conf");

  assert.match(
    contents,
    /listen\s+80\s+default_server;[\s\S]*listen\s+443\s+ssl;[\s\S]*server_name\s+www\.mscqr\.com\s+_/,
    "www app server must listen on both forwarded HTTP and direct TLS"
  );
  assert.match(contents, /location\s+=\s+\/healthz\s*\{[\s\S]*return\s+200\s+"ok\\n";/, "healthz must remain direct");
  assert.match(
    contents,
    /location\s+~\s+\^\/api\/health\/\?\(\.\*\)\$\s*\{[\s\S]*proxy_pass\s+http:\/\/backend:4000\/health\/\$1;/,
    "API readiness proxy must remain reachable"
  );
});

test("release deploy verifier fails homepage redirects with evidence", () => {
  const contents = readRepoFile("ops/deploy/deploy.yml");

  assert.match(contents, /url:\s+https:\/\/www\.mscqr\.com\/healthz[\s\S]*status_code:\s+200[\s\S]*follow_redirects:\s+none/);
  assert.match(contents, /url:\s+https:\/\/www\.mscqr\.com\/[\s\S]*follow_redirects:\s+none/);
  assert.match(contents, /curl\s+-sS\s+-I\s+-L\s+--max-redirs\s+8/);
  assert.match(contents, /Observed status=\{\{\s+homepage_check\.status/);
  assert.match(contents, /Redirect-chain stdout=\{\{\s+homepage_redirect_chain\.stdout_lines/);
});
