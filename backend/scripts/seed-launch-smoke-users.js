#!/usr/bin/env node
"use strict";

const refuse = () => ({
  ok: false,
  code: "PROHIBITED_PROTECTED_ENVIRONMENT_SEED",
  diagnostic: "Launch-smoke account mutation is prohibited against protected database identities.",
});

if (require.main === module) {
  console.log(JSON.stringify(refuse()));
  process.exitCode = 1;
}

module.exports = { refuse };
