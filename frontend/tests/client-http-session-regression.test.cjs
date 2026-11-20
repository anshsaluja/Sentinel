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

function deferred() {
  let resolve;
  const promise = new Promise(done => { resolve = done; });
  return { promise, resolve };
}

test('logout cancellation wins over a late HTTP 403 response', async () => {
  const started = deferred();
  const response = deferred();
  const api = new SentinelApiClient(() => 'session-a', undefined, async () => {
    started.resolve();
    return response.promise;
  });
  const pending = api.pendingApprovals();
  await started.promise;
  api.cancelPendingRequests();
  response.resolve({ ok: false, status: 403 });
  await assert.rejects(pending, error => error instanceof SentinelApiError &&
    error.status === null && /cancelled or timed out/.test(error.message));
});

test('token rotation wins over a late HTTP 401 response', async () => {
  let token = 'session-a';
  const started = deferred();
  const response = deferred();
  const api = new SentinelApiClient(() => token, undefined, async () => {
    started.resolve();
    return response.promise;
  });
  const pending = api.pendingApprovals();
  await started.promise;
  token = 'session-b';
  response.resolve({ ok: false, status: 401 });
  await assert.rejects(pending, error => error instanceof SentinelApiError &&
    error.status === 401 && /authentication changed/.test(error.message));
});

test('ordinary HTTP 403 still returns sanitized HTTP status', async () => {
  const api = new SentinelApiClient(() => 'session-a', undefined, async () => ({
    ok: false, status: 403, text: async () => 'private server details',
  }));
  await assert.rejects(api.pendingApprovals(), error => error instanceof SentinelApiError &&
    error.status === 403 && /HTTP 403/.test(error.message) &&
    !error.message.includes('private server details'));
});
