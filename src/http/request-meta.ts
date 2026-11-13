/**
 * Facts about a request that only the server knows, such as the TCP peer address.
 *
 * Everything inside a Web `Request` (URL, headers) comes from the client and can be forged. The
 * peer address cannot: it is the socket the bytes arrived on. HTTP adapters (`@strutvane/auth/node`,
 * `@strutvane/auth/hono`) attach it here, keyed by the `Request` object in a `WeakMap`, so:
 * - client headers can never set or override it (there is no header to spoof), and
 * - it is garbage-collected together with the request.
 *
 * Rate limiting and trusted-proxy handling read it through {@link requestMeta}.
 *
 * @module
 */

/** Server-side facts about one request. */
export interface RequestMeta {
  /** The TCP peer address (`socket.remoteAddress`), e.g. `"203.0.113.7"` or `"::1"`. */
  readonly remoteAddress?: string
}

const metas = new WeakMap<object, RequestMeta>()

/** Attach server-side facts to a request. Call this in the HTTP adapter, before authentication. */
export function attachRequestMeta<R extends object>(request: R, meta: RequestMeta): R {
  metas.set(request, Object.freeze({ ...meta }))
  return request
}

/** Server-side facts for a request, or `undefined` when no adapter attached any. */
export function requestMeta(request: object): RequestMeta | undefined {
  return metas.get(request)
}
