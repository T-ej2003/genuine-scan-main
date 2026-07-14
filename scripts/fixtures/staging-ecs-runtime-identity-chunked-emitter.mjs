#!/usr/bin/env node
import process from "node:process";

const stream = process.argv[2] === "stderr" ? process.stderr : process.stdout;
if (!stream.isTTY) process.exit(2);
for (const chunk of [
  "MSCQR_DB_IDEN", "TITY_BEGIN\n",
  '{"database_name":"mscqr_staging",', '"database_user":"mscqr_staging_app"}\n',
  "MSCQR_DB_IDENT", "ITY_END\n",
]) {
  stream.write(chunk);
  await new Promise((resolve) => setTimeout(resolve, 5));
}
