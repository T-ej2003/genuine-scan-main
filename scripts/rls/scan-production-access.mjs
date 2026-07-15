#!/usr/bin/env node
import { buildWorkflowManifest, rel, workflowManifestPath } from "./lib/program-inventory.mjs";

const manifest = buildWorkflowManifest();
console.log(JSON.stringify({ output: rel(workflowManifestPath), workflows: manifest.workflows.length, productionAccessSites: manifest.generatedEvidence.productionAccessSites, potentiallyDeadAccessSites: manifest.generatedEvidence.unregisteredPotentiallyDeadAccesses.length }));
