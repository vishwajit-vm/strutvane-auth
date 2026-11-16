/**
 * Constant-time string comparison.
 *
 * @module
 */
import { createHash, timingSafeEqual } from 'node:crypto'

/**
 * Compare two strings without leaking, through timing, how many leading characters match.
 *
 * Both sides are hashed first, so inputs of different lengths still take the same path
 * (`timingSafeEqual` itself throws on a length mismatch, which would be its own oracle).
 *
 * @example
 * ```ts
 * if (!safeEqual(presentedDigest, storedDigest)) throw new AuthError('INVALID_TOKEN')
 * ```
 */
export function safeEqual(a: string, b: string): boolean {
  const ha = createHash('sha256').update(a, 'utf8').digest()
  const hb = createHash('sha256').update(b, 'utf8').digest()
  return timingSafeEqual(ha, hb)
}
