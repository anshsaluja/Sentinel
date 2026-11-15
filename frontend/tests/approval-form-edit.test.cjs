'use strict';

const assert = require('node:assert/strict');
const { readFileSync } = require('node:fs');
const { join } = require('node:path');
const test = require('node:test');

// Source contracts for the Angular request form. These are not component tests.
const source = readFileSync(join(__dirname, '..', 'src', 'main.ts'), 'utf8');
const method = source.split('async submitApproval(): Promise<void> {')[1]?.split('\n  async loadApprovals():')[0];

test('submission captures both fields before calling the API', () => {
  assert.ok(method, 'submitApproval must exist');
  assert.match(method, /const submittedResource = this\.requestedResource\(\);/);
  assert.match(method, /const submittedJustification = this\.requestJustification\(\);/);
  assert.match(method, /this\.api\.createApproval\(submittedResource, submittedJustification\)/);
});

test('successful submission only clears fields that still match submitted values', () => {
  assert.match(method, /if \(this\.requestedResource\(\) === submittedResource\) this\.requestedResource\.set\(''\)/);
  assert.match(method, /if \(this\.requestJustification\(\) === submittedJustification\) this\.requestJustification\.set\(''\)/);
});

test('session invalidation protects submission success and finalizer', () => {
  assert.match(method, /if \(epoch === this\.sessionEpoch\) \{/);
  assert.match(method, /if \(epoch === this\.sessionEpoch\) this\.requestLoading\.set\(false\)/);
});

// Exercise the conditional clearing semantics separately from Angular's signals.
function clearUnchanged(current, submitted) {
  return current === submitted ? '' : current;
}

test('unchanged fields clear after success', () => {
  assert.equal(clearUnchanged('ledger', 'ledger'), '');
  assert.equal(clearUnchanged('Need access', 'Need access'), '');
});

test('edits made during submission survive success independently', () => {
  assert.equal(clearUnchanged('payments', 'ledger'), 'payments');
  assert.equal(clearUnchanged('Updated reason', 'Need access'), 'Updated reason');
  assert.equal(clearUnchanged('ledger', 'ledger'), '');
  assert.equal(clearUnchanged('Updated reason', 'Need access'), 'Updated reason');
});
