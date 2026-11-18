/**
 * The unique key of a passkey row. A WebAuthn credential id can be up to 1024 characters
 * (base64url), longer than MySQL can index, so the `passkeys` table keeps the id itself in a
 * text column and enforces uniqueness on its SHA-256 (64 hex characters). It is not a secret:
 * the credential id is public, and the hash only makes it indexable everywhere.
 *
 * @module
 */
import { createHash } from 'node:crypto'

/**
 * The `credential_key` column for a credential id.
 *
 * @example
 * credentialKey('AbC') // 64 lowercase hex characters
 */
export function credentialKey(credentialId: string): string {
  return createHash('sha256').update(credentialId, 'utf8').digest('hex')
}
