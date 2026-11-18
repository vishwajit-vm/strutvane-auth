import { defineConfig } from 'vitest/config'

// Integration tests against a throwaway PostgreSQL 18 container (started and removed by the
// global setup; no Docker files are written, ADR-0006).
export default defineConfig({
  test: {
    include: ['test/integration/**/*.test.ts'],
    globalSetup: ['test/global-setup.ts', 'test/integration/global-setup.ts'],
    environment: 'node',
    testTimeout: 60_000,
    hookTimeout: 180_000,
    passWithNoTests: false,
    allowOnly: false,
    fileParallelism: false,
  },
})
