/**
 * A second duck-iam engine in a separate OS process, spawned by `e2e-invalidation-cross-instance.e2e.test.ts`.
 * Newline-delimited JSON over stdio. Env: PG_URL, REDIS_PORT, CHANNEL, SECRET (empty = unsigned), TTL_SECONDS.
 */
import { and, eq, or } from 'drizzle-orm'
import { drizzle } from 'drizzle-orm/node-postgres'
import { Pool } from 'pg'
import { IamDrizzleAdapter } from '../../../adapters/drizzle'
import { iamAssignments, iamPolicies, iamRoles, iamSubjectAttrs } from '../../../adapters/drizzle/pg'
import { IamEngine } from '../../../core/engine/engine'
import { createIamRedisInvalidator } from '../index'
import { pubSubOver, RedisConn, waitFor } from './e2e-invalidation-redis'

type Action = 'read'
type Res = 'post'
type Role = 'admin'

function env(name: string): string {
  const v = process.env[name]
  if (v === undefined) throw new Error(`[worker] missing env ${name}`)
  return v
}

function say(value: unknown): void {
  process.stdout.write(`${JSON.stringify(value)}\n`)
}

async function main(): Promise<void> {
  const channel = env('CHANNEL')
  const secretRaw = env('SECRET')
  const pool = new Pool({ connectionString: env('PG_URL'), max: 4 })
  const db = drizzle(pool)
  const port = Number(env('REDIS_PORT'))
  const pub = await RedisConn.open(port)
  const sub = await RedisConn.open(port)

  const engine = new IamEngine<Action, Res, Role, string, 'production'>({
    adapter: new IamDrizzleAdapter<Action, Res, Role, string>({
      db,
      ops: { and, eq, or },
      tables: { assignments: iamAssignments, attrs: iamSubjectAttrs, policies: iamPolicies, roles: iamRoles },
    }),
    cacheTTL: Number(env('TTL_SECONDS')),
    invalidator: createIamRedisInvalidator<Role>({
      channel,
      client: pubSubOver(pub, sub),
      secret: secretRaw.length === 0 ? null : secretRaw,
    }),
    mode: 'production',
  })

  const ready = await waitFor(async () => {
    const r = await pub.command('PUBSUB', 'NUMSUB', channel)
    return Array.isArray(r) && Number(r[1]) >= 1
  }, 15_000)
  if (ready === null) throw new Error('[worker] never subscribed')
  say({ ready: true })

  let buffer = ''
  process.stdin.setEncoding('utf8')
  process.stdin.on('data', (chunk: string) => {
    buffer += chunk
    for (;;) {
      const nl = buffer.indexOf('\n')
      if (nl < 0) return
      const line = buffer.slice(0, nl)
      buffer = buffer.slice(nl + 1)
      if (line.trim().length === 0) continue
      void handle(JSON.parse(line))
    }
  })

  async function handle(msg: unknown): Promise<void> {
    if (typeof msg !== 'object' || msg === null) return
    const id = Reflect.get(msg, 'id')
    const cmd = Reflect.get(msg, 'cmd')
    const subject = Reflect.get(msg, 'subject')
    try {
      if (cmd === 'can' && typeof subject === 'string') {
        say({ allowed: await engine.can(subject, 'read', { attributes: {}, type: 'post' }), id })
        return
      }
      if (cmd === 'assign' && typeof subject === 'string') {
        await engine.admin.assignRole(subject, 'admin')
        say({ id, ok: true })
        return
      }
      if (cmd === 'revoke' && typeof subject === 'string') {
        await engine.admin.revokeRole(subject, 'admin')
        say({ id, ok: true })
        return
      }
      if (cmd === 'exit') {
        engine.dispose()
        pub.close()
        sub.close()
        await pool.end()
        say({ id, ok: true })
        process.exit(0)
      }
      say({ error: `unknown command ${String(cmd)}`, id })
    } catch (err) {
      say({ error: err instanceof Error ? err.message : String(err), id })
    }
  }
}

main().catch((err: unknown) => {
  process.stderr.write(`[worker] ${err instanceof Error ? err.stack : String(err)}\n`)
  process.exit(1)
})
