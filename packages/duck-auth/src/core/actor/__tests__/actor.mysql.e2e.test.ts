/** E2E: actor attribution through mysql2's pool, where a queued write is handed its connection by another's release. */
import type { RowDataPacket } from 'mysql2'
import { type Connection, createConnection, createPool, type Pool } from 'mysql2/promise'
import { afterAll, beforeAll, describe, expect, it } from 'vitest'
import { DrizzleMysqlAdapter } from '~/adapters/drizzle/mysql'
import { withActor } from '~/core/actor'
import { mysqlUrl } from '~/test/e2e-env'
import { MYSQL_DDL } from '~/test/schema-drift'
import { identityInput } from '~/test/store-inputs'

const MYSQL_URL = mysqlUrl()
const suite = MYSQL_URL ? describe : describe.skip

/** Its own database: the compliance suite truncates the shared one between cases. */
const DB = 'duckauth_e2e_actor'

type Profile = { username: string; email: string }

suite('E2E actor attribution through a one-connection MySQL pool', () => {
  let admin: Connection
  let pool: Pool
  let stores: DrizzleMysqlAdapter<Profile>

  beforeAll(async () => {
    admin = await createConnection({ multipleStatements: true, uri: MYSQL_URL })
    await admin.query(`DROP DATABASE IF EXISTS ${DB}; CREATE DATABASE ${DB}; USE ${DB}`)
    await admin.query(MYSQL_DDL)
    const url = new URL(MYSQL_URL ?? '')
    url.pathname = `/${DB}`
    // One connection, so every write below queues for it.
    pool = createPool({ connectionLimit: 1, uri: url.toString() })
    stores = new DrizzleMysqlAdapter<Profile>(pool)
  }, 60_000)

  afterAll(async () => {
    await pool?.end()
    await admin?.query(`DROP DATABASE IF EXISTS ${DB}`)
    await admin?.end()
  })

  it('stamps each queued write with the scope that made it, and a write outside every scope with no one', async () => {
    const actors = ['alice', undefined, 'bob', 'carol', 'dave', undefined]
    const create = (actor: string | undefined, i: number) =>
      withActor(actor, async () => {
        const name = `queued-${i}`
        return (
          await stores.identities.create(identityInput({ profile: { email: `${name}@actor.test`, username: name } }))
        ).id
      })
    const ids = await Promise.all(actors.map(create))
    // Linked under the reverse order, so no write can pass by reusing the actor its identity was created under.
    const linkers = [...actors].reverse()
    await Promise.all(
      ids.map((id, i) =>
        withActor(linkers[i], () => stores.identities.link(id, { providerId: 'github', providerSub: `sub-${i}` })),
      ),
    )

    const [identities] = await admin.query<RowDataPacket[]>('SELECT id, created_by, updated_by FROM auth_identities')
    const [links] = await admin.query<RowDataPacket[]>('SELECT identity_id, added_by FROM auth_identity_providers')
    const stamped = ids.map((id) => identities.find((row) => row.id === id))
    expect(stamped.map((row) => [row?.created_by, row?.updated_by])).toEqual(actors.map((a) => [a ?? null, a ?? null]))
    expect(ids.map((id) => links.find((row) => row.identity_id === id)?.added_by)).toEqual(
      linkers.map((a) => a ?? null),
    )
  })
})
