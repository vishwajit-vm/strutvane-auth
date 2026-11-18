import { defineConfig, mergeConfig } from 'vitest/config'
import { sharedConfig } from './vitest.shared.ts'

// The default gate runs everything that needs no Docker: unit tests, PGlite (in-process Postgres)
// equivalence/RLS tests and the identity contract on the native engine. Container tests (real
// PostgreSQL 18: pooling, session leaks, owner/superuser bypass, Better Auth) run with
// `npm run test:integration` (vitest.integration.config.ts).
export default mergeConfig(
  sharedConfig,
  defineConfig({
    test: {
      exclude: ['test/integration/**', 'node_modules/**', 'dist/**'],
      // The app schema (skeleton users table + auth's migrations), compiled once by the framework.
      globalSetup: ['test/global-setup.ts'],
      testTimeout: 30_000,
      // PGlite boots a full Postgres in-process; under a loaded machine that can exceed 10 s.
      hookTimeout: 60_000,
      coverage: {
        // The Better Auth adapter talks to a real Postgres; it is covered by the integration suite.
        exclude: ['src/**/*.test.ts', 'src/**/index.ts', 'src/identity/better-auth.ts'],
      },
    },
  }),
)
