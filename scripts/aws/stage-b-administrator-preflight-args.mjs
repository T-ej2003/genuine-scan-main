const launcherValueOptions = new Set(["--phase", "--output", "--signature-output", "--lifecycle-directory"]);
const launcherBooleanOptions = new Set(["--retry"]);
const planBoundOnlyOptions = new Set(["--report-generator-caller-arn", "--simulated-role-arn", "--plan-json", "--canonical-plan-json", "--saved-plan", "--plan-approval-report", "--plan-approval-report-sha256", "--manifest", "--expected-account", "--expected-region", "--policy-published-at", "--cloudtrail-session-name", "--reference-audit", "--refresh-report"]);

export function parseStageBAdministratorPreflightArgs(argv) {
  const values = new Map();
  const seen = new Set();
  const forwarded = [];

  for (let index = 0; index < argv.length; index += 1) {
    const argument = argv[index];
    if (launcherBooleanOptions.has(argument)) {
      if (seen.has(argument)) throw new Error(`${argument} may be specified only once.`);
      seen.add(argument);
      continue;
    }
    if (launcherValueOptions.has(argument)) {
      if (seen.has(argument)) throw new Error(`${argument} may be specified only once.`);
      const value = argv[index + 1];
      if (!value || value.startsWith("--")) throw new Error(`${argument} requires a value.`);
      seen.add(argument);
      values.set(argument, value);
      index += 1;
      continue;
    }
    forwarded.push(argument);
  }

  const required = (name) => {
    const value = values.get(name);
    if (!value) throw new Error(`${name} is required.`);
    return value;
  };
  const phase = required("--phase");
  if (!["initial", "plan-bound"].includes(phase)) throw new Error("--phase must be initial or plan-bound.");
  if (phase === "initial" && forwarded.some((argument) => planBoundOnlyOptions.has(argument))) throw new Error("Initial administrator capability preflight does not accept plan-bound arguments.");

  return {
    phase,
    outputPath: required("--output"),
    signaturePath: required("--signature-output"),
    lifecycleDirectory: required("--lifecycle-directory"),
    retry: seen.has("--retry"),
    forwarded,
  };
}
