#!/usr/bin/env node
// Retired before reading staging files or mutating release artifacts/metadata.
// Keep the command as an actionable failure for existing automation.
throw new Error('Unsigned Windows ZIP publication is retired. Use the governed signed Windows candidate/release workflow; AllSigned and application-control protections must remain enabled.');
