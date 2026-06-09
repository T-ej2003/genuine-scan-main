import "dotenv/config";

import prisma from "../src/config/database";
import { getLegacyQrReport, serializeLegacyQrReportCsv } from "../src/services/legacyQrRotationService";
import { runLegacyQrRiskReportJob } from "../src/services/legacyQrRiskReportJobService";

const args = new Set(process.argv.slice(2));
const valueAfter = (name: string) => {
  const index = process.argv.indexOf(name);
  return index >= 0 ? process.argv[index + 1] || "" : "";
};

const main = async () => {
  const report = await getLegacyQrReport();
  const format = args.has("--csv") ? "csv" : "json";
  const outputPath = valueAfter("--out").trim();
  const outputDir = valueAfter("--out-dir").trim();

  if (args.has("--scheduled")) {
    const result = await runLegacyQrRiskReportJob({ outputDir: outputDir || null });
    process.stdout.write(
      `${JSON.stringify(
        {
          generatedAt: result.report.generatedAt,
          totalLegacyCodes: result.report.totalLegacyCodes,
          potentiallyRotatableLegacyCodes: result.report.potentiallyRotatableLegacyCodes,
          knownUnsafeLegacyCodes: result.report.knownUnsafeLegacyCodes,
          localArtifacts: result.localArtifacts,
          objectStorage: result.objectStorage,
          comparison: result.comparison,
        },
        null,
        2
      )}\n`
    );
    return;
  }

  const payload = format === "csv" ? `${serializeLegacyQrReportCsv(report)}\n` : `${JSON.stringify(report, null, 2)}\n`;
  if (outputPath) {
    const { writeFileSync } = await import("fs");
    writeFileSync(outputPath, payload, "utf8");
  } else {
    process.stdout.write(payload);
  }

  process.stderr.write(
    [
      `legacy_total=${report.totalLegacyCodes}`,
      `potentially_rotatable=${report.potentiallyRotatableLegacyCodes}`,
      `known_unsafe=${report.knownUnsafeLegacyCodes}`,
    ].join(" ") + "\n"
  );
};

main()
  .catch((error) => {
    console.error(error);
    process.exitCode = 1;
  })
  .finally(async () => {
    await prisma.$disconnect();
  });
