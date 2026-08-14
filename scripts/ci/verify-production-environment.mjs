import { assertProductionEnvironmentContract, assertProductionEnvironmentRepository } from "./production-environment-contract.mjs";

const repository = process.env.GITHUB_REPOSITORY;
const token = process.env.GITHUB_TOKEN;
if (!repository || !token) throw new Error("GITHUB_REPOSITORY and GITHUB_TOKEN are required.");
assertProductionEnvironmentRepository(repository);
const headers = { Accept: "application/vnd.github+json", Authorization: `Bearer ${token}`, "X-GitHub-Api-Version": "2022-11-28" };
const base = `https://api.github.com/repos/${repository}`;
const response = await fetch(`${base}/environments/production`, { headers });
if (!response.ok) throw new Error(`Unable to read production environment (${response.status}).`);
const environment = await response.json();
const policyResponse = await fetch(`${base}/environments/production/deployment-branch-policies`, { headers });
if (!policyResponse.ok) throw new Error(`Unable to read production deployment branch policies (${policyResponse.status}).`);
const branchPolicies = (await policyResponse.json()).branch_policies;
process.stdout.write(`${JSON.stringify(assertProductionEnvironmentContract({ environment, branchPolicies }))}\n`);
