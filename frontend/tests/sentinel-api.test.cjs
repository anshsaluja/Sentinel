'use strict';
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const test = require('node:test');
const Module = require('node:module');
const ts = require('typescript');

// Compile the actual API transport using the frontend's existing TypeScript dependency.
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

test('signed-out requests fail without contacting the API', async () => {
  let called = false;
  const api = new SentinelApiClient(() => null, undefined, async () => { called = true; });
  await assert.rejects(api.evaluate({}), e => e instanceof SentinelApiError && e.status === 401);
  assert.equal(called, false);
});

test('evaluation sends bearer token and JSON to the correct endpoint', async () => {
  let request;
  const api = new SentinelApiClient(() => 'test-token', undefined, async (url, options) => {
    request = { url: String(url), options };
    return { ok: true, json: async () => ({ allowed: true }) };
  });
  const payload = { request: { resourceId: 'report' }, rules: [] };
  assert.deepEqual(await api.evaluate(payload), { allowed: true });
  assert.equal(request.url, 'http://localhost:8080/api/v1/policies/evaluate');
  assert.equal(request.options.headers.Authorization, 'Bearer test-token');
  assert.equal(request.options.method, 'POST');
  assert.deepEqual(JSON.parse(request.options.body), payload);
  assert.equal(request.options.cache, 'no-store');
});

test('rejects remote and credential-bearing API origins', () => {
  for (const url of ['https://example.com', 'http://192.168.1.5:8080',
    'http://user:pass@localhost:8080', 'http://localhost:8080/?token=x']) {
    assert.throws(() => new SentinelApiClient(() => 'token', url));
  }
});

test('does not expose backend response bodies on errors', async () => {
  const api = new SentinelApiClient(() => 'token', undefined, async () => ({
    ok: false, status: 403, text: async () => 'sensitive backend details',
  }));
  await assert.rejects(api.simulate({}), e =>
    e instanceof SentinelApiError && e.status === 403 && !e.message.includes('sensitive'));
});

test('normalizes network errors without leaking exception details', async () => {
  const api = new SentinelApiClient(() => 'token', undefined, async () => {
    throw new Error('sensitive network details');
  });
  await assert.rejects(api.analyzeRisks({}), e =>
    e instanceof SentinelApiError && e.status === null && !e.message.includes('sensitive'));
});

test('risk comparison uses the expected endpoint', async () => {
  let endpoint;
  const api = new SentinelApiClient(() => 'token', undefined, async url => {
    endpoint = String(url);
    return { ok: true, json: async () => ({}) };
  });
  await api.compareRisks({});
  assert.equal(endpoint, 'http://localhost:8080/api/v1/risks/compare');
});

test('cancelPendingRequests aborts in-flight previews and clears request state', async () => {
  let started;
  const pending = new Promise(resolve => { started = resolve; });
  const api = new SentinelApiClient(() => 'token', undefined, async (_url, options) => {
    started(options.signal);
    return new Promise((_resolve, reject) => {
      options.signal.addEventListener('abort', () => reject(new Error('aborted')), { once: true });
    });
  });
  const request = api.evaluate({});
  const signal = await pending;
  assert.equal(signal.aborted, false);
  api.cancelPendingRequests();
  assert.equal(signal.aborted, true);
  await assert.rejects(request, e => e instanceof SentinelApiError &&
    e.status === null && /cancelled/.test(e.message));
  api.cancelPendingRequests(); // repeated logout is safe
});

test('logout during response parsing rejects the stale payload', async () => {
  let beginParsing;
  const parsing = new Promise(resolve => { beginParsing = resolve; });
  let finishParsing;
  const api = new SentinelApiClient(() => 'token', undefined, async () => ({
    ok: true,
    json: async () => {
      beginParsing();
      return new Promise(resolve => { finishParsing = resolve; });
    },
  }));
  const request = api.evaluate({});
  await parsing;
  api.cancelPendingRequests();
  finishParsing({ sensitive: 'previous session' });
  await assert.rejects(request, e => e instanceof SentinelApiError &&
    e.status === null && /cancelled/.test(e.message));
});

test('response from a previous authentication token is discarded', async () => {
  let currentToken = 'session-one';
  let finishParsing;
  let parsingStarted;
  const started = new Promise(resolve => { parsingStarted = resolve; });
  const api = new SentinelApiClient(() => currentToken, undefined, async (_url, options) => {
    assert.equal(options.headers.Authorization, 'Bearer session-one');
    return {
      ok: true,
      json: async () => {
        parsingStarted();
        return new Promise(resolve => { finishParsing = resolve; });
      },
    };
  });
  const request = api.evaluate({});
  await started;
  currentToken = 'session-two';
  finishParsing({ allowed: true });
  await assert.rejects(request, error =>
    error instanceof SentinelApiError && error.status === 401 &&
    /authentication changed/.test(error.message));
});

test('response is discarded if the token disappears while parsing', async () => {
  let currentToken = 'session-one';
  let finishParsing;
  let parsingStarted;
  const started = new Promise(resolve => { parsingStarted = resolve; });
  const api = new SentinelApiClient(() => currentToken, undefined, async () => ({
    ok: true,
    json: async () => {
      parsingStarted();
      return new Promise(resolve => { finishParsing = resolve; });
    },
  }));
  const request = api.analyzeRisks({});
  await started;
  currentToken = null;
  finishParsing({ findings: [] });
  await assert.rejects(request, error =>
    error instanceof SentinelApiError && error.status === 401);
});
