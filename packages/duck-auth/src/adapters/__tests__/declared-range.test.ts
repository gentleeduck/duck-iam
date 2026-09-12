import { readFileSync } from 'node:fs'
import { join } from 'node:path'
import { describe, expect, it } from 'vitest'
import { AdapterStore } from '~/adapters/adapter'
import { DrizzleMysqlAdapter } from '~/adapters/drizzle/mysql/mysql'
import { DrizzlePgAdapter } from '~/adapters/drizzle/pg/pg'
import { DrizzleSqliteAdapter } from '~/adapters/drizzle/sqlite/sqlite'
import { MemoryAdapter } from '~/adapters/memory/memory'
import type { AuthError } from '~/core/errors'

/** Enough of a drizzle handle to reach the end of a constructor; nothing here runs a query. */
const HANDLE = { run: () => undefined, select: () => undefined }

const ADAPTERS: readonly (readonly [file: string, store: AdapterStore<AuthError.Code>])[] = [
  ['memory/memory.ts', new MemoryAdapter()],
  ['drizzle/pg/pg.ts', new DrizzlePgAdapter(HANDLE as never)],
  ['drizzle/mysql/mysql.ts', new DrizzleMysqlAdapter(HANDLE as never)],
  ['drizzle/sqlite/sqlite.ts', new DrizzleSqliteAdapter(HANDLE as never)],
]

/** Read off the instance, not restated here: a store wired to the wrong map would otherwise pass. */
function declared(store: AdapterStore<AuthError.Code>): ReadonlySet<string> {
  const map = Reflect.get(store, 'toError')
  return (map as { codes: ReadonlySet<string> }).codes
}

function raised(file: string): readonly string[] {
  const source = readFileSync(join(__dirname, '..', file), 'utf8')
  return [...new Set([...source.matchAll(/new AuthError\('(AUTH_[A-Z_]+)'/g)].map(([, code]) => code as string))].sort()
}

describe('every adapter raises only what its map declares', () => {
  // A code outside the range is re-labelled AUTH_ADAPTER_FAILED by `wrap()`, so a 409 a caller retries on
  // and a 404 it branches on both reach it as an unhandled 500. The memory adapter did exactly that.
  it.each(ADAPTERS)('%s', (file, store) => {
    const codes = declared(store)
    expect(raised(file).filter((code) => !codes.has(code))).toEqual([])
  })

  it('finds the codes it is meant to be reading', () => {
    expect(raised('memory/memory.ts')).toContain('AUTH_STALE_WRITE')
    expect(raised('drizzle/pg/pg.ts')).toContain('AUTH_SESSION_REVOKED')
  })
})
