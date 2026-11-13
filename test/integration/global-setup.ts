/**
 * Starts ONE throwaway PostgreSQL 18 container for the integration run and removes it afterwards
 * (also on failure). Each test file creates its own database inside it. No Docker files are
 * written (ADR-0006); the container runs with `--rm` and binds to 127.0.0.1 on a random port.
 */
import { execFileSync } from 'node:child_process'
import { randomBytes } from 'node:crypto'
import pg from 'pg'
import type { TestProject } from 'vitest/node'

const IMAGE = 'postgres:18.7-alpine'

declare module 'vitest' {
  export interface ProvidedContext {
    pgAdminUrl: string
  }
}

function docker(...args: string[]): string {
  return execFileSync('docker', args, {
    encoding: 'utf8',
    stdio: ['ignore', 'pipe', 'pipe'],
  }).trim()
}

async function waitForPostgres(url: string, timeoutMs: number): Promise<void> {
  const deadline = Date.now() + timeoutMs
  let lastError: unknown
  while (Date.now() < deadline) {
    const client = new pg.Client({ connectionString: url })
    try {
      await client.connect()
      await client.query('SELECT 1')
      await client.end()
      return
    } catch (error) {
      lastError = error
      await client.end().catch(() => undefined)
      await new Promise((r) => setTimeout(r, 500))
    }
  }
  throw new Error(`PostgreSQL did not become ready: ${String(lastError)}`)
}

export default async function setup(project: TestProject): Promise<() => void> {
  const password = randomBytes(12).toString('hex')
  const name = `sv-auth-it-${randomBytes(4).toString('hex')}`
  docker(
    'run',
    '--rm',
    '-d',
    '--name',
    name,
    '-e',
    `POSTGRES_PASSWORD=${password}`,
    '-p',
    '127.0.0.1::5432',
    IMAGE,
  )
  const remove = (): void => {
    try {
      docker('rm', '-f', name)
    } catch {
      // already gone
    }
  }
  try {
    const port = docker('port', name, '5432/tcp').split('\n')[0]?.split(':').pop()
    if (!port) throw new Error('could not read the mapped port')
    const url = `postgres://postgres:${password}@127.0.0.1:${port}/postgres`
    await waitForPostgres(url, 90_000)
    project.provide('pgAdminUrl', url)
  } catch (error) {
    remove()
    throw error
  }
  return remove
}
