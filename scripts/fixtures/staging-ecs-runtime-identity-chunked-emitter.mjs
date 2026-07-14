#!/usr/bin/env node
import fs from "node:fs";
import process from "node:process";

const mode = process.argv[2] || "stdout";
const stream = mode === "stderr" ? process.stderr : process.stdout;
if (!stream.isTTY) process.exit(2);
if (mode === "hang") {
  fs.writeFileSync(process.argv[3], `${process.pid}\n`);
  process.on("SIGTERM", () => process.exit(0));
  setInterval(() => {}, 1000);
} else if (mode === "flood") {
  stream.write("x".repeat(Number(process.argv[3]) || 2048));
} else {
  for (const chunk of [
    "MSCQR_DB_IDEN", "TITY_BEGIN\n",
    '{"database_name":"mscqr_staging",', '"database_user":"mscqr_staging_app"}\n',
    "MSCQR_DB_IDENT", "ITY_END\n",
  ]) {
    stream.write(chunk);
    await new Promise((resolve) => setTimeout(resolve, 5));
  }
}
