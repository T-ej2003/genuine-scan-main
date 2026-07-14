import {
  RUNTIME_IDENTITY_BEGIN as BEGIN,
  RUNTIME_IDENTITY_END as END,
  STAGING_DATABASE_ROLE_CONTEXT as C,
} from "../lib/staging-database-role-credentials-core.mjs";

const identity = JSON.stringify({ database_name: C.databaseName, database_user: C.roles.app });
const block = (payload = identity, newline = "\n") => `${BEGIN}${newline}${payload}${newline}${END}${newline}`;

export const runtimeIdentityParserFixtures = Object.freeze([
  { name: "stdout-only", result: { status: 0, stdout: block(), stderr: "" }, expected: "ok" },
  { name: "stderr-only", result: { status: 0, stdout: "", stderr: block() }, expected: "ok" },
  { name: "session-manager-banner", result: { status: 0, stdout: `The Session Manager plugin was installed successfully.\nStarting session.\n${block()}`, stderr: "" }, expected: "ok" },
  { name: "ansi-framing", result: { status: 0, stdout: `\u001b[32m${BEGIN}\u001b[0m\n${identity}\n\u001b[32m${END}\u001b[0m\n`, stderr: "" }, expected: "ok" },
  { name: "crlf", result: { status: 0, stdout: block(identity, "\r\n"), stderr: "" }, expected: "ok" },
  { name: "split-json-lines", result: { status: 0, stdout: block(`{\n  "database_name": "${C.databaseName}",\n  "database_user": "${C.roles.app}"\n}`), stderr: "" }, expected: "ok" },
  { name: "surrounding-whitespace", result: { status: 0, stdout: `  ${BEGIN}  \n\n  ${identity}  \n\n  ${END}  \n`, stderr: "" }, expected: "ok" },
  { name: "stderr-session-framing", result: { status: 0, stdout: "Starting session with SessionId: fixture\n", stderr: `session framing\n${block()}session closed\n` }, expected: "ok" },
  { name: "command-failed", result: { status: 1, stdout: "", stderr: "session closed" }, expected: "command_failed" },
  { name: "command-terminated-without-status", result: { status: null, stdout: "", stderr: "session terminated" }, expected: "command_failed" },
  { name: "valid-exit-missing-identity", result: { status: 0, stdout: "Starting session.\nExiting session.\n", stderr: "" }, expected: "delimiters_missing" },
  { name: "invalid-json", result: { status: 0, stdout: block("{not-json}"), stderr: "" }, expected: "invalid_json" },
  { name: "unexpected-json-fields", result: { status: 0, stdout: block(JSON.stringify({ database_name: C.databaseName, database_user: C.roles.app, extra: true })), stderr: "" }, expected: "invalid_json" },
  { name: "unexpected-database", result: { status: 0, stdout: block(JSON.stringify({ database_name: "postgres", database_user: C.roles.app })), stderr: "" }, expected: "unexpected_database" },
  { name: "unexpected-user", result: { status: 0, stdout: block(JSON.stringify({ database_name: C.databaseName, database_user: C.runtimeAdminRole })), stderr: "" }, expected: "unexpected_user" },
]);
