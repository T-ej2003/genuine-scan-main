import "dotenv/config";
import path from "path";
import dotenv from "dotenv";

import prisma from "../src/config/database";
import { refreshAnalyticsRollups } from "../src/services/analyticsRollupService";

dotenv.config({ path: path.resolve(__dirname, "../.env") });

const run = async () => {
  const result = await refreshAnalyticsRollups();
  console.log(JSON.stringify(result, null, 2));
};

void run()
  .catch((error) => {
    console.error(error);
    process.exitCode = 1;
  })
  .finally(async () => {
    await prisma.$disconnect().catch(() => undefined);
  });
