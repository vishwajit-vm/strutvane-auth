/**
 * Compiles the app schema (skeleton users table + auth's migrations) once per test run and hands
 * it to every worker (see `test/support/auth-schema.ts`).
 */
import type { TestProject } from 'vitest/node'
import { computeAuthSchema } from './support/compile-auth-schema.ts'

export default async function setup(project: TestProject): Promise<void> {
  project.provide('authSchema', await computeAuthSchema())
}
