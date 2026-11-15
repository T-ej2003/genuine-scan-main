import assert from 'node:assert/strict';
import { downloadAppOnlyArtifact, parseAppOnlyArtifactReference, readCertifiedPrintingPredecessor } from './production-app-only-artifacts.mjs';
import { assertAppOnlyRequirements } from './production-app-only-requirements.mjs';
import { buildB03DeltaPackage } from './production-b03-delta-package.mjs';
import { buildB03ExecutorDefinition } from '../../infra/aws/terraform/lambda/production-rls-approval-broker/b03-approval.mjs';
import { STAGE_B } from './production-green-stage-b-contract.mjs';

export function validateB03RequirementReferences(references, sourceSha) {
  assert.deepEqual(Object.keys(references || {}).sort(), ['predecessor', 'successor']);
  const predecessorRef = parseAppOnlyArtifactReference(JSON.stringify(references.predecessor));
  const successorRef = parseAppOnlyArtifactReference(JSON.stringify(references.successor));
  assert.equal(predecessorRef.sourceSha, sourceSha);
  assert.equal(successorRef.sourceSha, sourceSha);
  return { predecessor: predecessorRef, successor: successorRef };
}

// Registration is infrastructure preparation, never permission to execute SQL.
export function produceB03ExecutorDefinition({ sourceSha, backendImage, references, run, repositoryRoot,
  download = downloadAppOnlyArtifact, validateSuccessor = assertAppOnlyRequirements, buildPackage = buildB03DeltaPackage }) {
  const { predecessor: predecessorRef, successor: successorRef } = validateB03RequirementReferences(references, sourceSha);
  const read = reference => JSON.parse(download({ kind: 'requirements', reference, repositoryRoot }).bytes);
  const predecessor = readCertifiedPrintingPredecessor({ sourceSha, reference: predecessorRef, repositoryRoot, download });
  const successor = read(successorRef);
  validateSuccessor(successor, { sourceSha, candidateSourceSha: sourceSha, repositoryRoot });
  const pkg = buildPackage({ predecessor, successor, repositoryRoot });
  const databases = JSON.parse(run(['rds', 'describe-db-instances', '--db-instance-identifier', STAGE_B.greenDatabaseIdentifier,
    '--output', 'json', '--no-cli-pager'])).DBInstances;
  assert.equal(databases?.length, 1); assert.equal(databases[0].DBInstanceIdentifier, STAGE_B.greenDatabaseIdentifier);
  assert.equal(databases[0].DBInstanceStatus, 'available'); assert.equal(databases[0].Engine, 'postgres');
  return buildB03ExecutorDefinition({ sourceSha, backendImage, package: pkg, databaseHostname: databases[0].Endpoint?.Address });
}
