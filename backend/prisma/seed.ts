const main = async () => {
  throw new Error("Prisma seed mutation is prohibited against protected database identities; use an explicit disposable development database fixture.");
};

main().catch((error) => {
  console.error(error instanceof Error ? error.message : "Prisma seed refused.");
  process.exitCode = 1;
});
