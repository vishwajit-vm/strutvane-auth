/**
 * Purpose-bound keys derived from the app key (`APP_KEY`).
 *
 * Why derive instead of using APP_KEY directly: each purpose gets an independent subkey (HKDF-SHA256
 * with a purpose label), so a signature made for one purpose (an email-verification link) can never
 * be replayed as another (a session digest), and a leak of one subkey reveals nothing about the
 * others.
 *
 * Why stored digests are KEYED (HMAC-SHA-256) and not plain SHA-256: session ids, reset links and
 * tokens have 256 bits of entropy, so plain SHA-256 would be safe for them, but recovery codes and
 * email digests do not. One keyed digest for everything keeps a database leak alone (backup, read-
 * only SQL bug) from being enough to brute-force the low-entropy ones. Trade-off: rotating APP_KEY
 * invalidates sessions, tokens and recovery codes (see README, open questions).
 *
 * @module
 */
import { createHmac, hkdfSync } from 'node:crypto'

/** Every purpose a subkey exists for. Adding one is a reviewed change. */
export type KeyPurpose =
  | 'session'
  | 'password-reset'
  | 'email-link'
  | 'email-link-nonce'
  | 'email-verification'
  | 'email-digest'
  | 'email-verification-hash'
  | 'recovery-code'
  | 'trusted-device'
  | 'two-factor-secret'
  | 'personal-access-token'
  | 'team-invitation'
  | 'webauthn-nonce'
  | 'webauthn-user-handle'
  | 'registration-nonce'

/**
 * The derived key ring.
 *
 * @example
 * ```ts
 * const keys = createKeyRing(process.env.APP_KEY ?? '')
 * const stored = keys.digest('session', rawSessionId)
 * ```
 */
export interface KeyRing {
  /** HMAC-SHA-256 of `value` under the purpose's subkey, as lowercase hex. */
  digest(purpose: KeyPurpose, value: string): string
  /** The raw 32-byte subkey (for AES-GCM and the WebAuthn user handle). */
  subkey(purpose: KeyPurpose): Buffer
}

const MIN_KEY_BYTES = 32

/** Decode `base64:…` (Laravel's APP_KEY format) or a raw string of at least 32 bytes. */
function decodeAppKey(appKey: string): Buffer {
  const bytes = appKey.startsWith('base64:')
    ? Buffer.from(appKey.slice('base64:'.length), 'base64')
    : Buffer.from(appKey, 'utf8')
  if (bytes.length < MIN_KEY_BYTES) {
    throw new RangeError(
      'APP_KEY must hold at least 32 bytes. Generate one with `node strut key:generate` (base64:…).',
    )
  }
  return bytes
}

/** Build the key ring from APP_KEY. Throws at boot (fail closed) when the key is too short. */
export function createKeyRing(appKey: string): KeyRing {
  const master = decodeAppKey(appKey)
  const cache = new Map<KeyPurpose, Buffer>()
  const subkey = (purpose: KeyPurpose): Buffer => {
    let key = cache.get(purpose)
    if (!key) {
      key = Buffer.from(
        hkdfSync('sha256', master, Buffer.alloc(0), `strutvane/auth/${purpose}`, 32),
      )
      cache.set(purpose, key)
    }
    return key
  }
  return Object.freeze({
    subkey,
    digest: (purpose: KeyPurpose, value: string) =>
      createHmac('sha256', subkey(purpose)).update(value, 'utf8').digest('hex'),
  })
}
