// Runs the sqlite dialect on a real SQLite (`node:sqlite` via drizzle's `sqlite-proxy`), so refused SQL fails here.
// Pins sqlite's one atomic `ON CONFLICT` upsert against mysql's read-then-branch, which races.

// WARN: `node:sqlite` loads without a flag on Node 22.13+; a CI pin to 22.5-22.12 needs `--experimental-sqlite`.
import { DatabaseSync } from 'node:sqlite'
import { and, eq, gt, inArray, isNull, or } from 'drizzle-orm'
import { drizzle } from 'drizzle-orm/sqlite-proxy'
import { describe, expect, it } from 'vitest'
import type { AccessControl } from '../../../core/types'
import type { IamDrizzle } from '../index'
import { IamDrizzleAdapter } from '../index'
import { iamAssignments, iamPolicies, iamRoles, iamSubjectAttrs } from '../sqlite'

/** Mirrors `sqlite.schema.ts`. Kept literal so a drift in either is visible here. */
const DDL = `
create table iam_policies (
  id text primary key not null, name text not null, description text, version integer not null default 1,
  algorithm text not null default 'deny-overrides', rules text not null, targets text,
  created_by text, updated_by text,
  created_at integer not null default (unixepoch()*1000), updated_at integer not null default (unixepoch()*1000)
);
create table iam_roles (
  id text primary key not null, name text not null, description text, permissions text not null,
  inherits text not null default '[]', scope text, metadata text, created_by text, updated_by text,
  created_at integer not null default (unixepoch()*1000), updated_at integer not null default (unixepoch()*1000)
);
create table iam_assignments (
  id text primary key not null, subject_id text not null, role_id text not null, scope text,
  starts_at integer, expires_at integer, attributes text, created_by text, updated_by text,
  created_at integer not null default (unixepoch()*1000), updated_at integer not null default (unixepoch()*1000)
);
create unique index uq_iam_assignments_subject_role_scope
  on iam_assignments (subject_id, role_id, coalesce(scope, ''));
create table iam_subject_attrs (
  subject_id text primary key not null, data text not null, created_by text, updated_by text,
  created_at integer not null default (unixepoch()*1000), updated_at integer not null default (unixepoch()*1000)
);
`

interface IGates {
  /** Awaited before the statement executes. */
  before?: (sql: string) => Promise<void> | void
  /** Awaited after it executes, before its rows are handed back to drizzle. */
  after?: (sql: string) => Promise<void> | void
}

/**
 * Real in-memory SQLite via drizzle's proxy driver. `log` records statements in order; the gates interleave writers.
 * NOTE: the mysql race sits between two statements, so `after` holds a writer once its read has answered "absent".
 */
function makeEngine(log: string[], gates?: IGates) {
  const raw = new DatabaseSync(':memory:')
  raw.exec(DDL)
  const db = drizzle(async (sql, params, method) => {
    log.push(sql)
    await gates?.before?.(sql)
    const stmt = raw.prepare(sql)
    if (method === 'run') {
      stmt.run(...(params as never[]))
      await gates?.after?.(sql)
      return { rows: [] }
    }
    const rows = stmt.all(...(params as never[])).map((r) => Object.values(r as object))
    await gates?.after?.(sql)
    return { rows: method === 'get' ? (rows[0] ?? []) : rows }
  })
  return { db, raw }
}

const TABLES = { assignments: iamAssignments, attrs: iamSubjectAttrs, policies: iamPolicies, roles: iamRoles }
const OPS = { and, eq, gt, inArray, isNull, or }

/**
 * Both dialects share one SQLite: the mysql branch emits a plain `SELECT ... LIMIT 1` and `INSERT`, which SQLite runs,
 * so the control measures the real mysql chain.
 */
function adapterFor(dialect: 'sqlite' | 'mysql', db: unknown, onPolicyError?: (err: Error) => void) {
  return new IamDrizzleAdapter<string, string, string, string, IamDrizzle.AnyDrizzleDb, typeof dialect>({
    ...(onPolicyError !== undefined && { onPolicyError }),
    db: db as IamDrizzle.AnyDrizzleDb,
    dialect,
    json: 'string',
    ops: OPS as unknown as IamDrizzle.IConfig<IamDrizzle.AnyDrizzleDb, typeof dialect>['ops'],
    tables: TABLES as unknown as IamDrizzle.IConfig<IamDrizzle.AnyDrizzleDb, typeof dialect>['tables'],
  })
}

function role(id: string, name: string): AccessControl.IRole<string, string, string> {
  return { description: '', id, inherits: [], name, permissions: [{ action: 'read', resource: 'post' }] }
}

const isSelect = (sql: string) => /^\s*select/i.test(sql)

/** INFO: drizzle wraps driver errors as `Failed query: <sql>` with the engine's text on `cause`, so walk the chain. */
function classify(err: unknown): string {
  for (let e: unknown = err; e instanceof Error; e = e.cause) {
    if (/UNIQUE constraint failed/i.test(e.message)) return 'threw: duplicate key'
  }
  return `threw: ${(err as Error).message}`
}

describe('drizzle sqlite dialect, against a real SQLite engine', () => {
  it('saveRole issues one atomic upsert, with no read in front of it', async () => {
    const log: string[] = []
    const { db, raw } = makeEngine(log)
    await adapterFor('sqlite', db).saveRole(role('r1', 'Reader'))

    expect({
      reads: log.filter(isSelect).length,
      statements: log.length,
      storedName: raw.prepare('select name from iam_roles where id = ?').get('r1'),
      usesOnConflict: log.some((s) => /on conflict/i.test(s)),
    }).toEqual({ reads: 0, statements: 1, storedName: { name: 'Reader' }, usesOnConflict: true })
  })

  it('CONTROL: the same call on the mysql dialect reads first, then writes', async () => {
    const log: string[] = []
    const { db } = makeEngine(log)
    await adapterFor('mysql', db).saveRole(role('r1', 'Reader'))

    // Without this control, `statements: 1` above only proves something ran once.
    expect({ reads: log.filter(isSelect).length, statements: log.length }).toEqual({ reads: 1, statements: 2 })
  })

  it('two interleaved saveRole calls for one id both succeed and leave one row', async () => {
    const log: string[] = []
    let releaseFirst: (() => void) | undefined
    const firstHeld = new Promise<void>((resolve) => {
      releaseFirst = resolve
    })
    let held = false
    const { db, raw } = makeEngine(log, {
      after: async () => {
        // Hold the first writer after its first statement. On sqlite that is the whole write, so there is no stale
        // read to invalidate; forcing sqlite onto the mysql branch turns this red.
        if (!held) {
          held = true
          await firstHeld
        }
      },
    })
    const adapter = adapterFor('sqlite', db)
    const settle = (p: Promise<unknown>) =>
      p.then(
        () => 'ok' as const,
        (e: Error) => `threw: ${e.message}`,
      )

    const first = settle(adapter.saveRole(role('r1', 'First')))
    const second = settle(adapter.saveRole(role('r1', 'Second')))
    await second
    releaseFirst?.()

    expect({
      outcomes: await Promise.all([first, second]),
      rows: raw.prepare('select id from iam_roles').all(),
    }).toEqual({ outcomes: ['ok', 'ok'], rows: [{ id: 'r1' }] })
  })

  it('CONTROL: the same interleaving on the mysql dialect raises the driver duplicate-key error', async () => {
    const log: string[] = []
    let releaseFirst: (() => void) | undefined
    const firstHeld = new Promise<void>((resolve) => {
      releaseFirst = resolve
    })
    let held = false
    const { db, raw } = makeEngine(log, {
      after: async (sql) => {
        // Hold the first writer once its read has *executed* and answered "row
        // absent" - the stale observation the second writer then invalidates.
        if (!held && isSelect(sql)) {
          held = true
          await firstHeld
        }
      },
    })
    const adapter = adapterFor('mysql', db)
    const settle = (p: Promise<unknown>) => p.then(() => 'ok' as const, classify)

    const first = settle(adapter.saveRole(role('r1', 'First')))
    const second = settle(adapter.saveRole(role('r1', 'Second')))
    await second
    releaseFirst?.()

    // Both writers saw no row and took the insert branch; the held writer's insert hits the primary key and throws.
    // INFO: mysql-only, the cost of MySQL having no target-scoped `ON CONFLICT`.
    expect({
      outcomes: await Promise.all([first, second]),
      rows: raw.prepare('select id from iam_roles').all(),
    }).toEqual({ outcomes: ['threw: duplicate key', 'ok'], rows: [{ id: 'r1' }] })
  })
})

const HOUR = 60 * 60 * 1000

describe('drizzle sqlite dialect: an elapsed assignment does not block its own re-grant', () => {
  it('assignRole revives an elapsed unscoped assignment instead of leaving it blocked forever', async () => {
    const { db } = makeEngine([])
    const adapter = adapterFor('sqlite', db)
    await adapter.saveRole(role('editor', 'Editor'))
    await adapter.assignRole('sub-1', 'editor', undefined, { expiresAt: new Date(Date.now() - 1000) })

    await adapter.assignRole('sub-1', 'editor')

    expect(await adapter.getSubjectRoles('sub-1')).toEqual(['editor'])
  })

  it('CONTROL: assignRole is still a no-op for an active duplicate', async () => {
    const { db, raw } = makeEngine([])
    const adapter = adapterFor('sqlite', db)
    await adapter.saveRole(role('editor', 'Editor'))
    await adapter.assignRole('sub-1', 'editor', undefined, { expiresAt: new Date(Date.now() + HOUR) })

    await adapter.assignRole('sub-1', 'editor', undefined, { attributes: { should: 'not-apply' } })

    const row = raw
      .prepare('select attributes from iam_assignments where subject_id = ? and role_id = ?')
      .get('sub-1', 'editor')
    expect(row).toEqual({ attributes: null })
  })

  it('assignRoleMany revives an elapsed assignment for one row without disturbing an active sibling', async () => {
    const { db } = makeEngine([])
    const adapter = adapterFor('sqlite', db)
    await adapter.saveRole(role('editor', 'Editor'))
    await adapter.saveRole(role('viewer', 'Viewer'))
    await adapter.assignRole('sub-1', 'editor', undefined, { expiresAt: new Date(Date.now() - 1000) })
    await adapter.assignRole('sub-1', 'viewer', undefined, { expiresAt: new Date(Date.now() + HOUR) })

    await adapter.assignRoleMany([
      { roleId: 'editor', subjectId: 'sub-1' },
      { roleId: 'viewer', subjectId: 'sub-1' },
    ])

    const rolesAfter = await adapter.getSubjectRoles('sub-1')
    expect(rolesAfter).toContain('editor')
    expect(rolesAfter).toContain('viewer')
    expect(rolesAfter).toHaveLength(2)
  })

  it('CONTROL: assignRoleMany is still a no-op for an active duplicate', async () => {
    const { db, raw } = makeEngine([])
    const adapter = adapterFor('sqlite', db)
    await adapter.saveRole(role('editor', 'Editor'))
    await adapter.assignRole('sub-1', 'editor', undefined, { expiresAt: new Date(Date.now() + HOUR) })

    const changed = await adapter.assignRoleMany([{ roleId: 'editor', subjectId: 'sub-1' }])

    expect(changed).toEqual([])
    const row = raw
      .prepare('select expires_at from iam_assignments where subject_id = ? and role_id = ?')
      .get('sub-1', 'editor')
    expect(row).not.toEqual({ expires_at: null })
  })
})

describe('drizzle setSubjectAttributes when the read fails, against a real SQLite engine', () => {
  const isAttrRead = (sql: string) => isSelect(sql) && /iam_subject_attrs/i.test(sql)
  const storedData = (raw: DatabaseSync) =>
    raw.prepare('select data from iam_subject_attrs where subject_id = ?').get('u1')
  const messages = (err: unknown): string => {
    const out: string[] = []
    for (let e: unknown = err; e instanceof Error; e = e.cause) out.push(e.message)
    return out.join(' <- ')
  }

  function seeded() {
    const log: string[] = []
    const failing = { read: false }
    const { db, raw } = makeEngine(log, {
      before: (sql) => {
        if (failing.read && isAttrRead(sql)) throw new Error('SQLITE_BUSY: database is locked')
      },
    })
    const errors: Error[] = []
    const adapter = adapterFor('sqlite', db, (err) => errors.push(err))
    return { adapter, errors, failing, log, raw }
  }

  it('CONTROL: a healthy merge keeps the attribute the call did not name', async () => {
    const { adapter, raw } = seeded()
    await adapter.setSubjectAttributes('u1', { suspended: true, tier: 'gold' })
    await adapter.setSubjectAttributes('u1', { tier: 'silver' })
    expect(JSON.parse(String(storedData(raw)?.data))).toEqual({ suspended: true, tier: 'silver' })
  })

  it('a failed read refuses the write and lands nothing', async () => {
    const { adapter, failing, log, raw } = seeded()
    await adapter.setSubjectAttributes('u1', { suspended: true, tier: 'gold' })
    const before = storedData(raw)
    failing.read = true
    const writesBefore = log.filter((sql) => !isSelect(sql)).length

    const outcome = await adapter.setSubjectAttributes('u1', { tier: 'silver' }).then(
      () => 'resolved',
      (err: unknown) => messages(err),
    )

    expect(outcome).toContain('SQLITE_BUSY')
    expect(storedData(raw)).toEqual(before)
    expect(log.filter((sql) => !isSelect(sql)).length).toBe(writesBefore)
  })

  it('a failed read is not reported as a policy error', async () => {
    const { adapter, errors, failing } = seeded()
    failing.read = true
    await adapter.setSubjectAttributes('u1', { tier: 'silver' }).catch(() => undefined)
    expect(errors).toEqual([])
  })

  it('a corrupt row is still overwritten, so the operator is not locked out, and it is reported', async () => {
    const { adapter, errors, raw } = seeded()
    raw.prepare('insert into iam_subject_attrs (subject_id, data) values (?, ?)').run('u1', '{not-json')

    await adapter.setSubjectAttributes('u1', { tier: 'silver' })

    expect(JSON.parse(String(storedData(raw)?.data))).toEqual({ tier: 'silver' })
    expect(errors.length).toBeGreaterThan(0)
  })

  it('a row that parses but is not a flat bag is corruption too', async () => {
    const { adapter, raw } = seeded()
    raw.prepare('insert into iam_subject_attrs (subject_id, data) values (?, ?)').run('u1', '["not","a","bag"]')
    await expect(adapter.getSubjectAttributes('u1')).rejects.toThrow(/corrupted attributes/)

    await adapter.setSubjectAttributes('u1', { tier: 'silver' })
    expect(JSON.parse(String(storedData(raw)?.data))).toEqual({ tier: 'silver' })
  })
})
