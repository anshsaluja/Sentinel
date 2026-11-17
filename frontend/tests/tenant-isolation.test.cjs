'use strict';
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const test = require('node:test');
const Module = require('node:module');
const ts = require('typescript');

// Exercise the real TypeScript transport, not a duplicated validator.
const source = path.resolve(__dirname, '../src/sentinel-api.ts');
const compiled = ts.transpileModule(fs.readFileSync(source, 'utf8'), {
  compilerOptions: { module: ts.ModuleKind.CommonJS, target: ts.ScriptTarget.ES2022 },
  fileName: source, reportDiagnostics: true,
});
assert.deepEqual(
  (compiled.diagnostics || []).filter(d => d.category === ts.DiagnosticCategory.Error),
  [],
);
const mod = new Module(source, module);
mod.filename = source;
mod.paths = Module._nodeModulePaths(path.dirname(source));
mod._compile(compiled.outputText, source);
const { SentinelApiClient, SentinelApiError } = mod.exports;

const request = {
  id: 'request-1',
  tenantId: 'tenant-a',
  requesterId: 'alice',
  approverId: null,
  resourceId: 'ledger',
  justification: 'Quarterly review',
  status: 'PENDING',
  version: 1,
  updatedAt: '2026-11-17T12:00:00Z',
};

function clientFor(queue) {
  return new SentinelApiClient(() => 'test-reviewer-token', undefined, async () => ({
    ok: true,
    json: async () => queue,
  }));
}

test('rejects a pending queue containing requests from different tenants', async () => {
  const queue = [request, { ...request, id: 'request-2', tenantId: 'tenant-b' }];
  await assert.rejects(clientFor(queue).pendingApprovals(), error =>
    error instanceof SentinelApiError && error.status === null &&
    error.message === 'Invalid approval queue response');
});

test('accepts multiple distinct requests for the same tenant', async () => {
  const queue = [request, { ...request, id: 'request-2', requesterId: 'bob' }];
  assert.deepEqual(await clientFor(queue).pendingApprovals(), queue);
});

test('accepts empty pending queue without inferring a tenant', async () => {
  assert.deepEqual(await clientFor([]).pendingApprovals(), []);
});

test('rejects mixed-tenant queues regardless of item ordering', async () => {
  const second = { ...request, id: 'request-2', tenantId: 'tenant-b' };
  for (const queue of [[request, second], [second, request]]) {
    await assert.rejects(clientFor(queue).pendingApprovals(), SentinelApiError);
  }
});

test('rejects missing, blank, and non-string tenant identifiers', async () => {
  for (const tenantId of [undefined, null, '', '   ', 42]) {
    await assert.rejects(
      clientFor([{ ...request, tenantId }]).pendingApprovals(),
      error => error instanceof SentinelApiError &&
        error.message === 'Invalid approval queue response',
    );
  }
});

test('rejects duplicate approval IDs even within a single tenant', async () => {
  const queue = [request, { ...request, requesterId: 'bob' }];
  await assert.rejects(clientFor(queue).pendingApprovals(), SentinelApiError);
});

test('rejects non-pending entries rather than showing them in reviewer queue', async () => {
  for (const status of ['APPROVED', 'REJECTED', 'CANCELLED', 'UNKNOWN']) {
    await assert.rejects(
      clientFor([{ ...request, status }]).pendingApprovals(),
      SentinelApiError,
    );
  }
});

test('rejects malformed approval identifiers and unsafe versions', async () => {
  for (const id of ['', '.', '..', '../other', 'a/b', 'x'.repeat(121)]) {
    await assert.rejects(clientFor([{ ...request, id }]).pendingApprovals(), SentinelApiError);
  }
  for (const version of [-1, 1.5, Number.MAX_SAFE_INTEGER + 1, '1', null]) {
    await assert.rejects(clientFor([{ ...request, version }]).pendingApprovals(), SentinelApiError);
  }
});

test('rejects impossible, timezone-free, and malformed approval timestamps', async () => {
  for (const updatedAt of [
    '2026-02-30T12:00:00Z', '2026-11-17T12:00:00',
    '2026-11-17T25:00:00Z', 'not-a-date', null,
  ]) {
    await assert.rejects(clientFor([{ ...request, updatedAt }]).pendingApprovals(), SentinelApiError);
  }
});

test('rejects blank required approval fields and invalid approver identities', async () => {
  for (const field of ['requesterId', 'resourceId', 'justification']) {
    await assert.rejects(clientFor([{ ...request, [field]: '   ' }]).pendingApprovals(), SentinelApiError);
  }
  for (const approverId of ['', '   ', 42]) {
    await assert.rejects(clientFor([{ ...request, approverId }]).pendingApprovals(), SentinelApiError);
  }
});
