const protocol = "postgresql";
const user = "mscqr_p2_test";
const host = "127.0.0.1";
const port = "55432";
const database = "mscqr_p2_admin_test";

const args = new Set(process.argv.slice(2));

if (args.has("--print-admin-url")) {
  process.stdout.write(`${protocol}://${user}@${host}:${port}/${database}`);
} else {
  console.log("P2 test DB uses local trust auth on 127.0.0.1 for disposable Postgres only.");
}
