/** The pg schema's own declarations, against the DDL a deployment is handed. */

import { getTableConfig } from 'drizzle-orm/pg-core'
import { describe, it } from 'vitest'
import {
  PG_DDL as DDL,
  declaredNames,
  expectDdlDeclaresNothingExtra,
  expectSchemaReachesDdl,
} from '~/test/schema-drift'
import { authCredentials, authIdentities, authIdentityProviders, authSessions } from '../pg.schema'

const TABLES = [authIdentities, authIdentityProviders, authCredentials, authSessions]

describe('every pg declaration reaches the generated DDL', () => {
  it.each(TABLES.map((t) => [getTableConfig(t).name, t] as const))('%s', (name, table) => {
    expectSchemaReachesDdl(DDL, declaredNames(getTableConfig(table)), name)
  })

  it('carries nothing the schema no longer declares', () => {
    expectDdlDeclaresNothingExtra(
      DDL,
      TABLES.flatMap((t) => declaredNames(getTableConfig(t))),
      'pg',
    )
  })
})
