/**
 * A software WebAuthn authenticator (ES256, attestation "none") so the passkey flows run against
 * the REAL @simplewebauthn/server verification, with no browser. It builds authenticator data,
 * CBOR attestation objects and DER signatures exactly as a platform authenticator would.
 */
import { createHash, generateKeyPairSync, type KeyObject, randomBytes, sign } from 'node:crypto'

type Cbor = number | string | Uint8Array | ReadonlyMap<number | string, Cbor> | readonly Cbor[]

function head(major: number, n: number): Buffer {
  if (n < 24) return Buffer.from([(major << 5) | n])
  if (n < 256) return Buffer.from([(major << 5) | 24, n])
  if (n < 65536) {
    const b = Buffer.alloc(3)
    b[0] = (major << 5) | 25
    b.writeUInt16BE(n, 1)
    return b
  }
  const b = Buffer.alloc(5)
  b[0] = (major << 5) | 26
  b.writeUInt32BE(n, 1)
  return b
}

/** A minimal CBOR encoder (ints, byte/text strings, arrays, maps). */
export function cbor(value: Cbor): Buffer {
  if (typeof value === 'number') return value >= 0 ? head(0, value) : head(1, -1 - value)
  if (typeof value === 'string') {
    const bytes = Buffer.from(value, 'utf8')
    return Buffer.concat([head(3, bytes.length), bytes])
  }
  if (value instanceof Uint8Array) return Buffer.concat([head(2, value.length), Buffer.from(value)])
  if (Array.isArray(value))
    return Buffer.concat([head(4, value.length), ...value.map((v: Cbor) => cbor(v))])
  const map = value as ReadonlyMap<number | string, Cbor>
  const parts: Buffer[] = [head(5, map.size)]
  for (const [k, v] of map) parts.push(cbor(k), cbor(v))
  return Buffer.concat(parts)
}

const b64u = (b: Uint8Array | string): string => Buffer.from(b).toString('base64url')
const sha256 = (b: Uint8Array | string): Buffer => createHash('sha256').update(b).digest()

interface Credential {
  readonly id: Buffer
  readonly privateKey: KeyObject
  readonly userHandle: string
  counter: number
}

/** Options shaped like simplewebauthn's JSON options (only the fields used). */
interface CreationOptions {
  readonly challenge: string
  readonly rp: { readonly id?: string }
  readonly user: { readonly id: string }
}
interface RequestOptions {
  readonly challenge: string
  readonly rpId?: string
  readonly allowCredentials?: readonly { readonly id: string }[]
}

/** A software authenticator holding any number of credentials. */
export class SoftAuthenticator {
  readonly credentials: Credential[] = []
  readonly origin: string
  constructor(origin: string) {
    this.origin = origin
  }

  /** Answer a registration ceremony; returns RegistrationResponseJSON. */
  register(
    options: CreationOptions,
    overrides: { readonly origin?: string; readonly challenge?: string } = {},
  ): Record<string, unknown> {
    const { privateKey, publicKey } = generateKeyPairSync('ec', { namedCurve: 'P-256' })
    const jwk = publicKey.export({ format: 'jwk' })
    const id = randomBytes(16)
    const cose = cbor(
      new Map<number, Cbor>([
        [1, 2],
        [3, -7],
        [-1, 1],
        [-2, Buffer.from(jwk.x ?? '', 'base64url')],
        [-3, Buffer.from(jwk.y ?? '', 'base64url')],
      ]),
    )
    const idLen = Buffer.alloc(2)
    idLen.writeUInt16BE(id.length)
    const authData = Buffer.concat([
      sha256(options.rp.id ?? 'localhost'),
      Buffer.from([0x45]), // UP | UV | AT
      Buffer.alloc(4), // counter 0
      Buffer.alloc(16), // aaguid
      idLen,
      id,
      cose,
    ])
    const clientData = JSON.stringify({
      type: 'webauthn.create',
      challenge: overrides.challenge ?? options.challenge,
      origin: overrides.origin ?? this.origin,
      crossOrigin: false,
    })
    const attestation = cbor(
      new Map<string, Cbor>([
        ['fmt', 'none'],
        ['attStmt', new Map()],
        ['authData', authData],
      ]),
    )
    this.credentials.push({ id, privateKey, userHandle: options.user.id, counter: 0 })
    return {
      id: b64u(id),
      rawId: b64u(id),
      type: 'public-key',
      clientExtensionResults: {},
      response: {
        clientDataJSON: b64u(clientData),
        attestationObject: b64u(attestation),
        transports: ['internal'],
      },
    }
  }

  /** Answer an authentication ceremony; returns AuthenticationResponseJSON. */
  assert(
    options: RequestOptions,
    overrides: {
      readonly credential?: Credential
      readonly uv?: boolean
      readonly origin?: string
      readonly keepCounter?: boolean
    } = {},
  ): Record<string, unknown> {
    const allowed = options.allowCredentials?.map((c) => c.id) ?? []
    const credential =
      overrides.credential ??
      this.credentials.find((c) => allowed.length === 0 || allowed.includes(b64u(c.id)))
    if (!credential) throw new Error('no matching credential')
    if (overrides.keepCounter !== true) credential.counter++
    const counter = Buffer.alloc(4)
    counter.writeUInt32BE(credential.counter)
    const authData = Buffer.concat([
      sha256(options.rpId ?? 'localhost'),
      Buffer.from([overrides.uv === false ? 0x01 : 0x05]),
      counter,
    ])
    const clientData = JSON.stringify({
      type: 'webauthn.get',
      challenge: options.challenge,
      origin: overrides.origin ?? this.origin,
    })
    const signature = sign(
      'sha256',
      Buffer.concat([authData, sha256(clientData)]),
      credential.privateKey,
    )
    return {
      id: b64u(credential.id),
      rawId: b64u(credential.id),
      type: 'public-key',
      clientExtensionResults: {},
      response: {
        clientDataJSON: b64u(clientData),
        authenticatorData: b64u(authData),
        signature: b64u(signature),
        userHandle: credential.userHandle,
      },
    }
  }
}
