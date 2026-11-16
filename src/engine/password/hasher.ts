/**
 * Password hashing with `node:crypto` scrypt, in a self-describing format with rehash-on-login.
 *
 * **Why scrypt and not argon2id.** argon2id is the first choice of OWASP's password storage cheat
 * sheet, and `@node-rs/argon2` 2.2.2 (MIT, checked 2026-11-15) has no install scripts. But it ships
 * a prebuilt native binary per platform through optional dependencies: an opaque `.node` file we
 * cannot review, one more supply-chain path, and a gap on platforms without a prebuild. scrypt is
 * memory-hard, is OWASP's listed alternative ("N=2^17, r=8, p=1"), and is built into Node, so the
 * core needs no dependency at all. The format below names its algorithm, so an argon2id hasher can
 * be added later and old hashes upgrade on the next login.
 *
 * **Format** (PHC-like): `$scrypt$ln=17,r=8,p=1$<salt b64>$<key b64>` with a 16-byte salt and a
 * 64-byte key. Parameters live in the hash, so raising them later is safe: `needsRehash()` tells
 * the login flow to re-hash with the new ones (Laravel's `rehash_on_login`).
 *
 * **Legacy hashes** (an import from Laravel's bcrypt, say) plug in as {@link LegacyVerifier}s. They
 * are only ever verified, then replaced by scrypt on the next successful login.
 *
 * @module
 */
import { randomBytes, scrypt, timingSafeEqual } from 'node:crypto'

/** scrypt cost parameters. `logN` is log2 of N. */
export interface ScryptParams {
  readonly logN: number
  readonly r: number
  readonly p: number
}

/** OWASP's scrypt recommendation (cheat sheet, checked 2026-11-15): 128 MiB, one lane. */
export const DEFAULT_SCRYPT: ScryptParams = Object.freeze({ logN: 17, r: 8, p: 1 })

/**
 * Verifies a non-scrypt hash format (bcrypt, argon2, PBKDF2) from an import.
 *
 * @example
 * ```ts
 * const bcrypt: LegacyVerifier = {
 *   id: 'bcrypt',
 *   matches: (h) => h.startsWith('$2y$'),
 *   verify: (pw, h) => bcryptVerify(pw, h),
 * }
 * ```
 */
export interface LegacyVerifier {
  readonly id: string
  matches(stored: string): boolean
  verify(password: string, stored: string): Promise<boolean>
}

/**
 * Hashes and verifies passwords.
 *
 * @example
 * ```ts
 * const hasher = createScryptHasher()
 * const stored = await hasher.hash('correct horse battery staple')
 * await hasher.verify('correct horse battery staple', stored) // true
 * hasher.needsRehash(stored) // false until the parameters change
 * ```
 */
export interface PasswordHasher {
  hash(password: string): Promise<string>
  /** True when `password` matches `stored`. Never throws for a malformed `stored`; it is false. */
  verify(password: string, stored: string): Promise<boolean>
  /** True when `stored` is a legacy format or uses weaker parameters than the current ones. */
  needsRehash(stored: string): boolean
  /**
   * Burn the same time as a real verification and return false. Called when there is no user (or
   * no password) so the response time does not reveal which emails have accounts.
   */
  verifyDummy(password: string): Promise<false>
}

/**
 * The most work and memory one verification may cost, for stored rows AND for the hasher's own
 * parameters (so it never writes a hash it would refuse). Why a product bound and not per-field
 * ranges: `logN`, `r` and `p` multiply, so ranges that each look sane (logN 16, r 32, p 16) still
 * allow 32x the default work from one tampered row, a CPU denial of service per sign-in attempt.
 * - work `N * r * p` at most 2^23 (logN 20, r 8, p 1; the default is 2^20);
 * - memory `128 * N * r` at most 1 GiB.
 */
const MAX_WORK = 2 ** 23
const MAX_MEMORY = 2 ** 30

/** True when `params` are within the budget above (and each field is a sane integer). */
export function scryptParamsWithinBudget(params: ScryptParams): boolean {
  const { logN, r, p } = params
  if (
    ![logN, r, p].every(Number.isInteger) ||
    logN < 10 ||
    logN > 20 ||
    r < 1 ||
    r > 32 ||
    p < 1 ||
    p > 16
  )
    return false
  const N = 2 ** logN
  return N * r * p <= MAX_WORK && 128 * N * r <= MAX_MEMORY
}

const FORMAT =
  /^\$scrypt\$ln=(\d{1,2}),r=(\d{1,2}),p=(\d{1,2})\$([A-Za-z0-9+/]{22})\$([A-Za-z0-9+/]{86})$/
const KEY_BYTES = 64

interface Parsed extends ScryptParams {
  readonly salt: Buffer
  readonly key: Buffer
}

function parse(stored: string): Parsed | undefined {
  const m = FORMAT.exec(stored)
  if (!m) return undefined
  const [, ln, r, p, salt, key] = m
  if (
    ln === undefined ||
    r === undefined ||
    p === undefined ||
    salt === undefined ||
    key === undefined
  )
    return undefined
  const params = { logN: Number(ln), r: Number(r), p: Number(p) }
  // Refuse absurd parameters instead of letting a tampered row pin the CPU or memory.
  if (!scryptParamsWithinBudget(params)) return undefined
  return { ...params, salt: Buffer.from(salt, 'base64'), key: Buffer.from(key, 'base64') }
}

function derive(password: string, salt: Buffer, params: ScryptParams): Promise<Buffer> {
  const N = 2 ** params.logN
  return new Promise((resolve, reject) => {
    scrypt(
      password.normalize('NFKC'),
      salt,
      KEY_BYTES,
      // maxmem must exceed 128 * N * r, or Node refuses the larger costs.
      { N, r: params.r, p: params.p, maxmem: 256 * N * params.r },
      (error, key) => (error ? reject(error) : resolve(key)),
    )
  })
}

const b64 = (buf: Buffer): string => buf.toString('base64').replace(/=+$/, '')

/**
 * Create the scrypt hasher. Tests pass a lower `logN` (14) to stay fast; production keeps 17.
 * Passwords are NFKC-normalised first (NIST SP 800-63B), so the same password typed on two
 * keyboards hashes the same.
 */
export function createScryptHasher(
  options: { readonly params?: ScryptParams; readonly legacy?: readonly LegacyVerifier[] } = {},
): PasswordHasher {
  const params = options.params ?? DEFAULT_SCRYPT
  if (params.logN < 14 || params.logN > 20)
    throw new RangeError('scrypt logN must be between 14 and 20')
  if (!scryptParamsWithinBudget(params))
    throw new RangeError(
      'scrypt parameters exceed the verification budget (N*r*p <= 2^23, 128*N*r <= 1 GiB)',
    )
  const legacy = options.legacy ?? []

  const hash = async (password: string): Promise<string> => {
    const salt = randomBytes(16)
    const key = await derive(password, salt, params)
    return `$scrypt$ln=${params.logN},r=${params.r},p=${params.p}$${b64(salt)}$${b64(key)}`
  }

  // A real hash with the current parameters, made once, lazily: verifying against it costs exactly
  // what a real verification costs.
  let dummy: Promise<string> | undefined
  const dummyHash = (): Promise<string> => {
    dummy ??= hash(randomBytes(32).toString('hex'))
    return dummy
  }

  const verify = async (password: string, stored: string): Promise<boolean> => {
    const parsed = parse(stored)
    if (parsed) {
      const candidate = await derive(password, parsed.salt, parsed)
      return candidate.length === parsed.key.length && timingSafeEqual(candidate, parsed.key)
    }
    const verifier = legacy.find((v) => v.matches(stored))
    if (verifier) {
      try {
        return await verifier.verify(password, stored)
      } catch {
        return false
      }
    }
    // An unknown format still costs a real verification (no timing difference) and fails.
    await verify(password, await dummyHash())
    return false
  }

  return Object.freeze({
    hash,
    verify,
    needsRehash(stored: string): boolean {
      const parsed = parse(stored)
      if (!parsed) return true
      return parsed.logN < params.logN || parsed.r < params.r || parsed.p < params.p
    },
    async verifyDummy(password: string): Promise<false> {
      await verify(password, await dummyHash())
      return false
    },
  })
}
