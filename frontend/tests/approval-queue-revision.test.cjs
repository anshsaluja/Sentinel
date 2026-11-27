'use strict';

const assert = require('node:assert/strict');
const { readFileSync } = require('node:fs');
const { join } = require('node:path');
const test = require('node:test');

// Source-level regression contracts for the Angular approval queue.
// These do not replace component tests with controlled asynchronous API responses.
const source = readFileSync(join(__dirname, '..', 'src', 'main.ts'), 'utf8');

test('queue load captures a new revision and guards successful responses', () => {
  assert.match(source, /const revision = \+\+this\.approvalsRevision;/);
  assert.match(source, /if \(epoch === this\.sessionEpoch && revision === this\.approvalsRevision\) this\.approvals\.set\(queue\)/);
});

test('outdated queue failures cannot overwrite newer errors', () => {
  const load = source.match(/async loadApprovals\(\): Promise<void> \{[\s\S]*?\n  \}/);
  assert.ok(load, 'approval queue loader must exist');
  // Both the fail-closed queue reset and error update must remain inside the
  // same session/revision guard. The catch block intentionally has braces.
  assert.match(load[0], /catch \(error\) \{\s*if \(epoch === this\.sessionEpoch && revision === this\.approvalsRevision\) \{\s*(?:\/\/[^\n]*\n\s*)*this\.approvals\.set\(\[\]\);\s*this\.approvalsError\.set\([^\n]*\);\s*\}/);
});

test('outdated queue finalizers cannot clear a newer loading state', () => {
  assert.match(source, /if \(epoch === this\.sessionEpoch && revision === this\.approvalsRevision\) this\.approvalsLoading\.set\(false\)/);
});

test('decision invalidates a pending load and releases its spinner', () => {
  assert.match(source, /const epoch = this\.sessionEpoch;\s*\+\+this\.approvalsRevision;\s*\/\/[^\n]*\n\s*this\.approvalsLoading\.set\(false\);\s*this\.decisionId\.set/);
});

test('authentication initialization invalidates previous queue loads', () => {
  assert.match(source, /async initialize\(\)[\s\S]*?const epoch = \+\+this\.sessionEpoch;\s*\+\+this\.approvalsRevision;/);
});

test('logout invalidates queue loads before clearing UI state', () => {
  assert.match(source, /logout\(\): void \{\s*this\.sessionEpoch\+\+;\s*\+\+this\.approvalsRevision;/);
});
