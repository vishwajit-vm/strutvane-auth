/**
 * `@strutvane/auth/testing`: the identity contract suite (run it against any engine) and helpers
 * for tests that need actors, requests, cookies or reset mail. Requires `vitest` (optional peer).
 *
 * @module
 */
export {
  CONTRACT_DEV_URL,
  CONTRACT_PROD_URL,
  CONTRACT_RATE_LIMITS,
  type EngineFactory,
  type EngineFactoryOptions,
  runIdentityContract,
} from './contract.ts'
export {
  actingAs,
  type BrowserRequestOptions,
  browserRequest,
  cookieAttributes,
  freshIp,
  type Jar,
  Mailbox,
  newJar,
  runAs,
  store,
  TEST_NEW_PASSWORD,
  TEST_PASSWORD,
  TEST_PROXY,
  testEmail,
} from './helpers.ts'
