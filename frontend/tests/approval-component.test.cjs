'use strict';
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const test = require('node:test');
const Module = require('node:module');
const ts = require('typescript');

// Transpile the actual component; mock only Angular's renderer and dependencies.
const filename = path.resolve(__dirname, '../src/main.ts');
const compiled = ts.transpileModule(fs.readFileSync(filename, 'utf8'), {
  fileName: filename, reportDiagnostics: true,
  compilerOptions: { module: ts.ModuleKind.CommonJS, target: ts.ScriptTarget.ES2022,
    experimentalDecorators: true, useDefineForClassFields: false },
});
assert.equal((compiled.diagnostics || []).filter(d => d.category === ts.DiagnosticCategory.Error).length, 0);
let App;
const oauth = { getAccessToken: () => 'token', configure() {},
  setupAutomaticSilentRefresh() {}, loadDiscoveryDocumentAndTryLogin: async () => {},
  hasValidAccessToken: () => true, getIdentityClaims: () => ({}),
  logOut() {}, initCodeFlow() {} };
function signal(initial) {
  let value = initial;
  const read = () => value;
  read.set = next => { value = next; };
  return read;
}
const mocks = {
  '@angular/core': { Component: () => klass => { App = klass; return klass; },
    inject: () => oauth, signal },
  '@angular/platform-browser': { bootstrapApplication: async () => {} },
  '@angular/common/http': { provideHttpClient: () => ({}) },
  'angular-oauth2-oidc': { OAuthService: class {}, provideOAuthClient: () => ({}) },
  './sentinel-api': { SentinelApiClient: class { cancelPendingRequests() {} } },
};
const originalWindow = global.window;
global.window = { location: { origin: 'http://localhost:4200' }, confirm: () => true };
try {
  const mod = new Module(filename, module);
  mod.filename = filename;
  mod.paths = Module._nodeModulePaths(path.dirname(filename));
  mod.require = name => Object.hasOwn(mocks, name) ? mocks[name] : require(name);
  mod._compile(compiled.outputText, filename);
} finally {
  if (originalWindow === undefined) delete global.window;
  else global.window = originalWindow;
}
assert.equal(typeof App, 'function');
const approval = { id: 'req-1', tenantId: 'local-demo', requesterId: 'alice',
  approverId: null, resourceId: 'ledger', justification: 'Audit',
  status: 'PENDING', version: 2, updatedAt: '2026-11-23T00:00:00Z' };
function deferred() {
  let resolve, reject;
  const promise = new Promise((done, fail) => { resolve = done; reject = fail; });
  return { promise, resolve, reject };
}
function setup(api) {
  const app = new App();
  app.authenticated.set(true);
  Object.assign(app.api, api);
  return app;
}
async function withConfirm(fn) {
  const previous = global.window;
  global.window = { confirm: () => true };
  try { await fn(); }
  finally {
    if (previous === undefined) delete global.window;
    else global.window = previous;
  }
}
test('failed queue refresh clears stale decisions', async () => {
  let decisions = 0;
  const app = setup({ pendingApprovals: async () => { throw Error('offline'); },
    decideApproval: async () => { decisions++; } });
  app.approvals.set([approval]);
  await app.loadApprovals();
  assert.deepEqual(app.approvals(), []);
  assert.match(app.approvalsError(), /offline/);
  await app.decide(approval, 'APPROVE');
  assert.equal(decisions, 0);
});
test('refresh in progress blocks decisions', async () => {
  const pending = deferred();
  let decisions = 0;
  const app = setup({ pendingApprovals: () => pending.promise,
    decideApproval: async () => { decisions++; } });
  app.approvals.set([approval]);
  const refresh = app.loadApprovals();
  await app.decide(approval, 'REJECT');
  assert.equal(decisions, 0);
  pending.resolve([approval]);
  await refresh;
  assert.equal(app.approvalsLoading(), false);
});
test('stale queue versions and removed references cannot be decided', async () => {
  let decisions = 0;
  const app = setup({ decideApproval: async () => { decisions++; } });
  app.approvals.set([{ ...approval, version: 3 }]);
  await app.decide(approval, 'APPROVE');
  app.approvals.set([]);
  await app.decide(approval, 'APPROVE');
  assert.equal(decisions, 0);
});
test('uncertain decision failure invalidates queue', async () => {
  await withConfirm(async () => {
    const app = setup({ decideApproval: async () => { throw Error('lost response'); } });
    app.approvals.set([approval]);
    await app.decide(approval, 'APPROVE');
    assert.deepEqual(app.approvals(), []);
    assert.match(app.approvalsError(), /Refresh approvals/);
    assert.equal(app.decisionId(), '');
  });
});
test('logout prevents outstanding queue response from repopulating UI', async () => {
  const pending = deferred();
  const app = setup({ pendingApprovals: () => pending.promise });
  const refresh = app.loadApprovals();
  app.logout();
  pending.resolve([approval]);
  await refresh;
  assert.deepEqual(app.approvals(), []);
  assert.equal(app.authenticated(), false);
});

test('concurrent decision attempts submit only one backend request', async () => {
  await withConfirm(async () => {
    const pending = deferred();
    const calls = [];
    const app = setup({
      decideApproval: (id, action, version) => {
        calls.push({ id, action, version });
        return pending.promise;
      },
    });
    app.approvals.set([approval]);
    const first = app.decide(approval, 'APPROVE');
    await app.decide(approval, 'REJECT');
    assert.deepEqual(calls, [{ id: approval.id, action: 'APPROVE', version: approval.version }]);
    assert.equal(app.decisionId(), approval.id);
    pending.resolve({ status: 'APPROVED' });
    await first;
    assert.equal(app.decisionId(), '');
    assert.deepEqual(app.approvals(), []);
    assert.match(app.approvalsNotice(), /approved/);
  });
});

test('refresh-time decision blocking preserves a single authoritative queue', async () => {
  await withConfirm(async () => {
    const pending = deferred();
    let decisions = 0;
    const app = setup({
      pendingApprovals: () => pending.promise,
      decideApproval: async () => { decisions++; },
    });
    app.approvals.set([approval]);
    const refresh = app.loadApprovals();
    await app.decide(approval, 'APPROVE');
    assert.equal(decisions, 0);
    pending.resolve([{ ...approval, version: 3 }]);
    await refresh;
    await app.decide(approval, 'APPROVE');
    assert.equal(decisions, 0);
    assert.equal(app.approvals()[0].version, 3);
  });
});

test('late failure from a signed-out session cannot clear a new session queue', async () => {
  const old = deferred();
  const fresh = deferred();
  const app = setup({ pendingApprovals: () => old.promise });
  const previous = app.loadApprovals();
  app.logout();
  app.authenticated.set(true);
  app.api.pendingApprovals = () => fresh.promise;
  const current = app.loadApprovals();
  const replacement = { ...approval, id: 'req-2', version: 3 };
  fresh.resolve([replacement]);
  await current;
  old.reject(Error('old session failure'));
  await previous;
  assert.deepEqual(app.approvals(), [replacement]);
  assert.equal(app.approvalsError(), '');
  assert.equal(app.approvalsLoading(), false);
});

test('late failure cannot clear a newer spinner or overwrite a newer refresh error', async () => {
  const old = deferred();
  const fresh = deferred();
  const app = setup({ pendingApprovals: () => old.promise });
  const previous = app.loadApprovals();
  app.logout();
  app.authenticated.set(true);
  app.api.pendingApprovals = () => fresh.promise;
  const current = app.loadApprovals();
  old.reject(Error('old session failure'));
  await previous;
  assert.equal(app.approvalsLoading(), true);
  assert.equal(app.approvalsError(), '');
  fresh.reject(Error('current refresh failure'));
  await current;
  assert.equal(app.approvalsError(), 'current refresh failure');
  assert.deepEqual(app.approvals(), []);
  assert.equal(app.approvalsLoading(), false);
});

test('late failure cannot replace an already displayed current refresh error', async () => {
  const old = deferred();
  const app = setup({ pendingApprovals: () => old.promise });
  const previous = app.loadApprovals();
  app.logout();
  app.authenticated.set(true);
  app.api.pendingApprovals = async () => { throw Error('current refresh failure'); };
  await app.loadApprovals();
  old.reject(Error('old session failure'));
  await previous;
  assert.equal(app.approvalsError(), 'current refresh failure');
  assert.deepEqual(app.approvals(), []);
  assert.equal(app.approvalsLoading(), false);
});
