'use strict';
const assert = require('node:assert/strict');
const test = require('node:test');
const fs = require('node:fs');
const path = require('node:path');
const Module = require('node:module');
const ts = require('typescript');

const file = path.resolve(__dirname, '../src/sentinel-api.ts');
const compiled = ts.transpileModule(fs.readFileSync(file, 'utf8'), {
  compilerOptions: { module: ts.ModuleKind.CommonJS, target: ts.ScriptTarget.ES2022 },
  fileName: file, reportDiagnostics: true,
});
assert.equal((compiled.diagnostics || []).filter(d => d.category === ts.DiagnosticCategory.Error).length, 0);
const mod = new Module(file, module);
mod.filename = file;
mod.paths = Module._nodeModulePaths(path.dirname(file));
mod._compile(compiled.outputText, file);
const { SentinelApiClient, SentinelApiError } = mod.exports;

test('missing authentication prevents any network request', async () => {
  let calls = 0;
  const api = new SentinelApiClient(() => null, undefined, async () => {
    calls++;
    throw new Error('unexpected fetch');
  });
  await assert.rejects(api.pendingApprovals(),
    error => error instanceof SentinelApiError && error.status === 401);
  assert.equal(calls, 0);
});

test('rotating authentication while JSON is parsed rejects stale responses', async () => {
  let token = 'session-a';
  let resolveBody;
  let bodyStarted;
  const parsing = new Promise(resolve => { bodyStarted = resolve; });
  const api = new SentinelApiClient(() => token, undefined, async () => ({
    ok: true,
    json: async () => {
      bodyStarted();
      return new Promise(resolve => { resolveBody = resolve; });
    },
  }));
  const pending = api.pendingApprovals();
  await parsing;
  token = 'session-b';
  resolveBody([]);
  await assert.rejects(pending,
    error => error instanceof SentinelApiError && error.status === 401 &&
      /authentication changed/.test(error.message));
});

test('logout cancellation rejects an in-flight response', async () => {
  let finish;
  let started;
  const fetching = new Promise(resolve => { started = resolve; });
  const api = new SentinelApiClient(() => 'session-a', undefined, async () => {
    started();
    return new Promise(resolve => { finish = resolve; });
  });
  const pending = api.pendingApprovals();
  await fetching;
  api.cancelPendingRequests();
  finish({ ok: true, json: async () => [] });
  await assert.rejects(pending,
    error => error instanceof SentinelApiError && error.status === null &&
      /cancelled or timed out/.test(error.message));
});
