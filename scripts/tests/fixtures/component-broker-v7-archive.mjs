import assert from "node:assert/strict";
import { brokerChangeEntryPoints, brokerEntryPoints } from "../../aws/component-broker-configuration.mjs";

// Immutable broker version 7 was built from 302a25d33bbe21093f1900277b806c3796e5e6e9.
// Preserve its exact archive-generation gate as a regression fixture.
export function assertHistoricalV7ArchiveEntryPoints(entryPoints) {
  assert(entryPoints === brokerEntryPoints || entryPoints === brokerChangeEntryPoints, "Unreviewed broker entry points");
}
