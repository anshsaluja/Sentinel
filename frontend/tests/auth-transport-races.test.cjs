'use strict';
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const test = require('node:test');
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

test('token rotation during a network failure rejects as session change', async () => {
  let currentToken = 'session-one';
  let failRequest;
  const api = new SentinelApiClient(() => currentToken, undefined, async () =>
    new Promise((_resolve, reject) => { failRequest = reject; }));
  const pending = api.evaluate({});
  currentToken = 'session-two';
  failRequest(new Error('internal network detail'));
  await assert.rejects(pending, error =>
    error instanceof SentinelApiError && error.status === 401 &&
    /authentication changed/.test(error.message) &&
    !error.message.includes('internal'));
});

test('token rotation during JSON parsing failure rejects as session change', async () => {
  let currentToken = 'session-one';
  let failParsing;
  let parsingStarted;
  const started = new Promise(resolve => { parsingStarted = resolve; });
  const api = new SentinelApiClient(() => currentToken, undefined, async () => ({
    ok: true,
    json: async () => {
      parsingStarted();
      return new Promise((_resolve, reject) => { failParsing = reject; });
    },
  }));
  const pending = api.simulate({});
  await started;
  currentToken = null;
  failParsing(new SyntaxError('private payload'));
  await assert.rejects(pending, error =>
    error instanceof SentinelApiError && error.status === 401 &&
    /authentication changed/.test(error.message) &&
    !error.message.includes('private'));
});

test('ordinary JSON parsing failure remains a sanitized transport error', async () => {
  const api = new SentinelApiClient(() => 'stable-session', undefined, async () => ({
    ok: true,
    json: async () => { throw new SyntaxError('sensitive response text'); },
  }));
  await assert.rejects(api.evaluate({}), error =>
    error instanceof SentinelApiError && error.status === null &&
    /Unable to reach/.test(error.message) &&
    !error.message.includes('sensitive'));
});
