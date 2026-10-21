import assert from 'node:assert/strict';
import {conditionalHash} from './production-cutover-conditional-authorization.mjs';
import {readConditionalPrepareAuthority} from './production-cutover-consumption-journal.mjs';
const contexts=new WeakMap();
export function createConditionalPrepareContext({authority,materialization}) {
  const approved=readConditionalPrepareAuthority(authority);
  assert.equal(materialization.manifest.derivationSha256,conditionalHash(approved.d));
  const context=Object.freeze({});contexts.set(context,{...approved,materialization:structuredClone(materialization)});return context;
}
export function readConditionalPrepareContext(context) {
  const value=contexts.get(context);assert.ok(value,'Authenticated conditional phase capability required');
  return {...value,d:structuredClone(value.d),materialization:structuredClone(value.materialization),successor:structuredClone(value.successor)};
}
