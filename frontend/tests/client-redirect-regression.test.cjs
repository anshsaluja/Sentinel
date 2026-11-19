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

test('approval decisions explicitly disable authenticated redirects', async () => {
  let seen;
  const api = new SentinelApiClient(() => 'reviewer-token', undefined, async (url, options) => {
    seen = { url: String(url), options };
    return { ok: false, status: 409 };
  });
  await assert.rejects(api.decideApproval('req-1', 'APPROVE', 1),
    e => e instanceof SentinelApiError && e.status === 409);
  assert.equal(seen.url, 'http://localhost:8080/api/v1/approvals/req-1/decision');
  assert.equal(seen.options.redirect, 'error');
  assert.equal(seen.options.cache, 'no-store');
  assert.equal(seen.options.headers.Authorization, 'Bearer reviewer-token');
});

test('approval creation explicitly disables authenticated redirects', async () => {
  let seen;
  const api = new SentinelApiClient(() => 'requester-token', undefined, async (_url, options) => {
    seen = options;
    return { ok: false, status: 403 };
  });
  await assert.rejects(api.createApproval('ledger', 'Business justification'),
    e => e instanceof SentinelApiError && e.status === 403);
  assert.equal(seen.redirect, 'error');
  assert.equal(seen.headers.Authorization, 'Bearer requester-token');
});

test('redirect transport errors do not leak target URLs', async () => {
  const api = new SentinelApiClient(() => 'reviewer-token', undefined, async () => {
    throw new TypeError('redirect to https://attacker.example/secret');
  });
  await assert.rejects(api.decideApproval('req-1', 'REJECT', 1),
    e => e instanceof SentinelApiError && e.status === null &&
    !e.message.includes('attacker.example') && /Unable to reach/.test(e.message));
});
