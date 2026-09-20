/**
 * `authCreateDrizzleMysqlOidcOpStores` takes any drizzle MySQL database, and the drivers disagree on what a
 * write answers: mysql2 gives `[ResultSetHeader]`, the serverless ones a `{ rowsAffected }` envelope. Both
 * `consume`s gate single-use on that number, so a shape the count cannot read refuses a code that is good.
 */
import { describe, expect, it } from 'vitest'
import { authCreateDrizzleMysqlOidcOpStores } from '../mysql'

const ROW = {
  clientId: 'app',
  code: 'c1',
  codeChallenge: null,
  codeChallengeMethod: null,
  exp: Date.now() + 60_000,
  identityId: 'u',
  nonce: null,
  redirectUri: 'https://app.test/cb',
  scope: JSON.stringify(['openid']),
  sid: 's',
  tenantId: null,
}

/** Only the calls `codes.consume` makes: the snapshot select, then the delete whose count picks the winner. */
function dbAnswering(deleted: unknown) {
  const tx = {
    delete: () => ({ where: async () => deleted }),
    select: () => ({ from: () => ({ where: () => ({ limit: async () => [ROW] }) }) }),
  }
  return { transaction: (run: (tx: unknown) => unknown) => run(tx) }
}

const consume = (deleted: unknown) =>
  authCreateDrizzleMysqlOidcOpStores(dbAnswering(deleted) as never).codes.consume('c1', Date.now())

describe('the write count each mysql driver answers with', () => {
  it('redeems a code when mysql2 reports one row deleted', async () => {
    expect((await consume([{ affectedRows: 1 }]))?.code).toBe('c1')
  })

  it('redeems a code when a serverless driver reports one row deleted', async () => {
    expect((await consume({ rowsAffected: 1 }))?.code).toBe('c1')
  })

  it('refuses the code when the delete removed nothing', async () => {
    expect(await consume([{ affectedRows: 0 }])).toBeNull()
  })
})
