import { defineConfig } from 'tsdown'

export default defineConfig({
  entry: {
    index: 'src/index.ts',
    sql: 'src/sql/index.ts',
    postgres: 'src/postgres/index.ts',
    'better-auth': 'src/identity/better-auth.ts',
    hono: 'src/middleware/hono.ts',
    node: 'src/middleware/node.ts',
    testing: 'src/testing/index.ts',
  },
  format: 'esm',
  platform: 'node',
  target: 'node24',
  dts: true,
  sourcemap: true,
  clean: true,
  // Optional peers and workspace packages stay external.
  deps: {
    neverBundle: [
      /^@strutvane\//,
      'better-auth',
      /^better-auth\//,
      'hono',
      /^hono\//,
      'pg',
      'vitest',
    ],
  },
})
