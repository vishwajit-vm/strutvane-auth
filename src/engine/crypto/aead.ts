/**
 * Authenticated encryption for secrets that must be recoverable (the TOTP secret).
 *
 * AES-256-GCM with a random 96-bit nonce. The `context` (the user id) is bound as additional
 * authenticated data, so a ciphertext copied from one user's row to another's fails to decrypt:
 * an attacker with write access to one column cannot transplant a known secret.
 *
 * Format: `v1.<nonce b64url>.<ciphertext b64url>.<tag b64url>`.
 *
 * @module
 */
import { createCipheriv, createDecipheriv, randomBytes } from 'node:crypto'

/**
 * Encrypt `plaintext` under a 32-byte key, bound to `context`.
 *
 * @example
 * ```ts
 * const sealed = seal(keys.subkey('two-factor-secret'), secret, user.id)
 * ```
 */
export function seal(key: Buffer, plaintext: string, context: string): string {
  const nonce = randomBytes(12)
  const cipher = createCipheriv('aes-256-gcm', key, nonce)
  cipher.setAAD(Buffer.from(context, 'utf8'))
  const body = Buffer.concat([cipher.update(plaintext, 'utf8'), cipher.final()])
  return ['v1', nonce, body, cipher.getAuthTag()]
    .map((part) => (typeof part === 'string' ? part : part.toString('base64url')))
    .join('.')
}

/** Decrypt a {@link seal} result; `undefined` when it was tampered with or bound to another context. */
export function open(key: Buffer, sealed: string, context: string): string | undefined {
  const [version, nonce, body, tag, extra] = sealed.split('.')
  if (
    version !== 'v1' ||
    nonce === undefined ||
    body === undefined ||
    tag === undefined ||
    extra !== undefined
  )
    return undefined
  const tagBytes = Buffer.from(tag, 'base64url')
  // Insist on the full 128-bit tag: GCM accepts truncated tags unless told otherwise, and a short
  // tag is far easier to forge (Node DEP0182).
  if (tagBytes.length !== 16) return undefined
  try {
    const decipher = createDecipheriv('aes-256-gcm', key, Buffer.from(nonce, 'base64url'), {
      authTagLength: 16,
    })
    decipher.setAAD(Buffer.from(context, 'utf8'))
    decipher.setAuthTag(tagBytes)
    return Buffer.concat([
      decipher.update(Buffer.from(body, 'base64url')),
      decipher.final(),
    ]).toString('utf8')
  } catch {
    return undefined
  }
}
