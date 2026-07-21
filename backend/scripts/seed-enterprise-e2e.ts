const main = async () => {
  throw new Error("Enterprise E2E mutation is prohibited against protected database identities; use a disposable test database.");
};

main().catch((error) => {
  console.error(error instanceof Error ? error.message : "Enterprise E2E seed refused.");
  process.exitCode = 1;
});
