#!/usr/bin/env node
"use strict";

console.log(JSON.stringify({
  ok: false,
  code: "PROHIBITED_PLATFORM_ROLE_REPAIR",
  diagnostic: "Direct platform administrator creation, promotion, or repair is prohibited; use the reviewed maker-checker administration path.",
  tokenLogged: false,
}));
process.exitCode = 1;
