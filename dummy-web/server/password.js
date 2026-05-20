/**
 * password.js — Connectly Secure Password Module
 *
 * Handles password hashing and verification using Node's built-in
 * crypto module with PBKDF2-SHA256.
 *
 * Flow:
 *   Registration → hashPassword(plaintext) → stores { salt, hash, iterations }
 *   Login        → verifyPassword(plaintext, stored) → true / false
 *
 * No plain-text passwords are ever stored. The salt is random per-user,
 * so two users with the same password produce completely different hashes.
 */

import crypto from 'crypto';

const ITERATIONS = 100_000;   // PBKDF2 iterations — high enough to resist brute-force
const KEY_LENGTH = 64;        // 512-bit output
const DIGEST     = 'sha256';
const ENCODING   = 'hex';

/**
 * Hash a plain-text password.
 * Returns an object to store in the user record.
 *
 * @param {string} plaintext
 * @returns {{ hash: string, salt: string, iterations: number }}
 */
export function hashPassword(plaintext) {
  const salt = crypto.randomBytes(32).toString(ENCODING);  // 256-bit random salt
  const hash = crypto.pbkdf2Sync(
    plaintext,
    salt,
    ITERATIONS,
    KEY_LENGTH,
    DIGEST
  ).toString(ENCODING);

  return { hash, salt, iterations: ITERATIONS };
}

/**
 * Verify a plain-text password against a stored hash record.
 * Uses timing-safe comparison to prevent timing attacks.
 *
 * @param {string} plaintext          — password the user just typed
 * @param {{ hash: string, salt: string, iterations: number }} stored — from user record
 * @returns {boolean}
 */
export function verifyPassword(plaintext, stored) {
  if (!plaintext || !stored?.hash || !stored?.salt) return false;

  const attempt = crypto.pbkdf2Sync(
    plaintext,
    stored.salt,
    stored.iterations || ITERATIONS,
    KEY_LENGTH,
    DIGEST
  ).toString(ENCODING);

  // Timing-safe compare — prevents timing-based attacks
  try {
    return crypto.timingSafeEqual(
      Buffer.from(attempt,      ENCODING),
      Buffer.from(stored.hash,  ENCODING)
    );
  } catch {
    return false;
  }
}