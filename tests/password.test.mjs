import test from 'node:test';
import assert from 'node:assert/strict';
import { hashPassword, verifyPassword } from '../dummy-web/server/password.js';

test('hashPassword stores only derived password material', () => {
  const stored = hashPassword('correct horse battery staple');

  assert.equal(typeof stored.hash, 'string');
  assert.equal(typeof stored.salt, 'string');
  assert.equal(stored.iterations, 100_000);
  assert.notEqual(stored.hash, 'correct horse battery staple');
  assert.notEqual(stored.salt, 'correct horse battery staple');
});

test('verifyPassword accepts the original password and rejects wrong input', () => {
  const stored = hashPassword('S3cure-demo-passphrase');

  assert.equal(verifyPassword('S3cure-demo-passphrase', stored), true);
  assert.equal(verifyPassword('wrong-password', stored), false);
  assert.equal(verifyPassword('', stored), false);
  assert.equal(verifyPassword('S3cure-demo-passphrase', null), false);
});

test('hashPassword uses a fresh salt for each hash', () => {
  const first = hashPassword('same-password');
  const second = hashPassword('same-password');

  assert.notEqual(first.salt, second.salt);
  assert.notEqual(first.hash, second.hash);
});
