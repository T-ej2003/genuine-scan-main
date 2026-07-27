#!/usr/bin/env node
import { buildTableManifest, rel, tableManifestPath } from "./lib/program-inventory.mjs";

const manifest = buildTableManifest();
console.log(JSON.stringify({ output: rel(tableManifestPath), tables: manifest.tables.length }));
