import { mkdtempSync, readFileSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import {
  __emitOpenapi,
  __envTemplate,
  __init,
  __keys,
  __migrate,
  __renderMigration,
  __scaffoldTemplate,
  run,
} from '../index'

describe('duck-auth CLI - scaffold templates', () => {
  it('quickstart scaffold names the in-memory adapter + scrypt hasher', () => {
    const text = __scaffoldTemplate('quickstart')
    expect(text).toContain('MemoryAuthAdapter')
    expect(text).toContain('ScryptHasher')
    expect(text).toContain('CookieTransport')
  })

  it('production scaffold names Redis + Argon2id + JwtTransport', () => {
    const text = __scaffoldTemplate('production')
    expect(text).toContain('RedisSessionStore')
    expect(text).toContain('Argon2idHasher')
    expect(text).toContain('JwtTransport')
    expect(text).toContain("env: 'production'")
  })

  it('env template includes the required vars + warning comment', () => {
    const env = __envTemplate()
    expect(env).toContain('DUCK_AUTH_BASE_URL')
    expect(env).toContain('DUCK_AUTH_HS256_SECRET')
    expect(env).toContain('REDIS_URL')
  })
})

describe('duck-auth CLI - init subcommand', () => {
  let workDir: string
  let originalCwd: string

  beforeEach(() => {
    workDir = mkdtempSync(join(tmpdir(), 'duck-auth-init-'))
    originalCwd = process.cwd()
    process.chdir(workDir)
  })

  afterEach(() => {
    process.chdir(originalCwd)
    rmSync(workDir, { recursive: true, force: true })
  })

  it('writes auth.ts + .env.duck-auth into target directory', async () => {
    const code = await __init(['my-auth'])
    expect(code).toBe(0)
    const authText = readFileSync(join(workDir, 'my-auth', 'auth.ts'), 'utf8')
    expect(authText).toContain('AuthRoot')
    const envText = readFileSync(join(workDir, 'my-auth', '.env.duck-auth'), 'utf8')
    expect(envText).toContain('DUCK_AUTH_BASE_URL')
  })

  it('--production flag emits the production scaffold', async () => {
    const code = await __init(['prod-auth', '--production'])
    expect(code).toBe(0)
    const authText = readFileSync(join(workDir, 'prod-auth', 'auth.ts'), 'utf8')
    expect(authText).toContain('RedisSessionStore')
  })

  it('refuses to overwrite an existing auth.ts', async () => {
    const stderr = vi.spyOn(process.stderr, 'write').mockImplementation(() => true)
    await __init(['x'])
    const code = await __init(['x'])
    expect(code).toBe(1)
    expect(stderr).toHaveBeenCalled()
    stderr.mockRestore()
  })
})

describe('duck-auth CLI - keys subcommand', () => {
  it('keys generate hs256 writes a base64url secret', async () => {
    const writes: string[] = []
    const spy = vi.spyOn(process.stdout, 'write').mockImplementation((chunk) => {
      writes.push(typeof chunk === 'string' ? chunk : chunk.toString())
      return true
    })
    const code = await __keys(['generate', 'hs256'])
    expect(code).toBe(0)
    const combined = writes.join('')
    expect(combined).toContain('DUCK_AUTH_HS256_SECRET')
    expect(combined).toMatch(/[A-Za-z0-9_-]{40,}/)
    spy.mockRestore()
  })

  it('keys generate ec256 writes PEM private + public', async () => {
    const writes: string[] = []
    const spy = vi.spyOn(process.stdout, 'write').mockImplementation((chunk) => {
      writes.push(typeof chunk === 'string' ? chunk : chunk.toString())
      return true
    })
    const code = await __keys(['generate', 'ec256'])
    expect(code).toBe(0)
    const combined = writes.join('')
    expect(combined).toContain('BEGIN PRIVATE KEY')
    expect(combined).toContain('BEGIN PUBLIC KEY')
    spy.mockRestore()
  })

  it('keys without args reports usage + exits 1', async () => {
    const stderr = vi.spyOn(process.stderr, 'write').mockImplementation(() => true)
    const code = await __keys([])
    expect(code).toBe(1)
    expect(stderr).toHaveBeenCalled()
    stderr.mockRestore()
  })

  it('keys with unknown algorithm reports + exits 1', async () => {
    const stderr = vi.spyOn(process.stderr, 'write').mockImplementation(() => true)
    const code = await __keys(['generate', 'rs2048'])
    expect(code).toBe(1)
    expect(stderr).toHaveBeenCalled()
    stderr.mockRestore()
  })
})

describe('duck-auth CLI - help / dispatch', () => {
  it('no args prints help + exits 0', async () => {
    const stdout = vi.spyOn(process.stdout, 'write').mockImplementation(() => true)
    const code = await run([])
    expect(code).toBe(0)
    expect(stdout).toHaveBeenCalled()
    stdout.mockRestore()
  })

  it('unknown command exits 1', async () => {
    const stdout = vi.spyOn(process.stdout, 'write').mockImplementation(() => true)
    const stderr = vi.spyOn(process.stderr, 'write').mockImplementation(() => true)
    const code = await run(['bogus'])
    expect(code).toBe(1)
    stdout.mockRestore()
    stderr.mockRestore()
  })
})

describe('duck-auth CLI - migrate', () => {
  it.each(['pg', 'mysql', 'sqlite'] as const)('renders DDL for %s with default prefix', (dialect) => {
    const ddl = __renderMigration(dialect, 'auth_')
    expect(ddl).toContain(`SqlBridge schema (${dialect})`)
    expect(ddl).toContain('CREATE TABLE IF NOT EXISTS auth_identities')
    expect(ddl).toContain('CREATE TABLE IF NOT EXISTS auth_credentials')
    expect(ddl).toContain('CREATE TABLE IF NOT EXISTS auth_sessions')
    expect(ddl).toContain('CREATE INDEX')
  })

  it('honors --prefix= flag', () => {
    const ddl = __renderMigration('pg', 'tenant_')
    expect(ddl).toContain('tenant_identities')
    expect(ddl).toContain('tenant_credentials')
    expect(ddl).toContain('tenant_sessions')
    expect(ddl).not.toContain('auth_identities')
  })

  it('pg uses bigint, sqlite uses INTEGER, mysql uses BIGINT', () => {
    expect(__renderMigration('pg', 'a_')).toContain('created_at bigint')
    expect(__renderMigration('mysql', 'a_')).toContain('created_at BIGINT')
    expect(__renderMigration('sqlite', 'a_')).toContain('created_at INTEGER')
  })

  it('rejects unknown dialect with exit 1', async () => {
    const stderr = vi.spyOn(process.stderr, 'write').mockImplementation(() => true)
    const code = await __migrate(['oracle'])
    expect(code).toBe(1)
    expect(stderr).toHaveBeenCalled()
    stderr.mockRestore()
  })

  it('writes to --out=path when supplied (relative path under cwd)', async () => {
    const dir = mkdtempSync(join(tmpdir(), 'duck-auth-migrate-'))
    const originalCwd = process.cwd()
    try {
      process.chdir(dir)
      const stdout = vi.spyOn(process.stdout, 'write').mockImplementation(() => true)
      const code = await __migrate(['sqlite', `--out=schema.sql`])
      expect(code).toBe(0)
      const written = readFileSync(join(dir, 'schema.sql'), 'utf8')
      expect(written).toContain('SqlBridge schema (sqlite)')
      stdout.mockRestore()
    } finally {
      process.chdir(originalCwd)
      rmSync(dir, { recursive: true, force: true })
    }
  })

  it('refuses --out=path that escapes cwd (containment guard)', async () => {
    const stderr = vi.spyOn(process.stderr, 'write').mockImplementation(() => true)
    const code = await __migrate(['sqlite', '--out=../../etc/duck-bogus.sql'])
    expect(code).toBe(1)
    expect(stderr).toHaveBeenCalled()
    stderr.mockRestore()
  })
})

describe('duck-auth CLI - keys rotate kid-collision guard', () => {
  it('rejects identical --prev-kid / --new-kid pair', async () => {
    const stderr = vi.spyOn(process.stderr, 'write').mockImplementation(() => true)
    const code = await __keys(['rotate', 'hs256', '--prev-kid=k1', '--new-kid=k1'])
    expect(code).toBe(1)
    expect(stderr).toHaveBeenCalled()
    stderr.mockRestore()
  })

  it('default --new-kid includes a random suffix (no collision on sub-second rotation)', async () => {
    const writes: string[] = []
    const spy = vi.spyOn(process.stdout, 'write').mockImplementation((chunk: string | Uint8Array) => {
      writes.push(typeof chunk === 'string' ? chunk : Buffer.from(chunk).toString())
      return true
    })
    const codeA = await __keys(['rotate', 'hs256', '--prev-kid=k1'])
    const codeB = await __keys(['rotate', 'hs256', '--prev-kid=k1'])
    expect(codeA).toBe(0)
    expect(codeB).toBe(0)
    // Pull kid lines from both runs; they must differ.
    const kidLines = writes.join('').match(/New signing kid: ([^.]+)\./g) ?? []
    expect(kidLines).toHaveLength(2)
    expect(kidLines[0]).not.toBe(kidLines[1])
    spy.mockRestore()
  })
})

describe('duck-auth CLI - keys rotate', () => {
  it('emits a new secret + rollover snippet referencing prev kid', async () => {
    const writes: string[] = []
    const spy = vi.spyOn(process.stdout, 'write').mockImplementation((chunk: string | Uint8Array) => {
      writes.push(typeof chunk === 'string' ? chunk : Buffer.from(chunk).toString())
      return true
    })
    const code = await __keys(['rotate', 'hs256', '--prev-kid=k7', '--new-kid=k8'])
    expect(code).toBe(0)
    const combined = writes.join('')
    expect(combined).toContain('rotation')
    expect(combined).toContain('k7')
    expect(combined).toContain('k8')
    expect(combined).toContain('verifyKeys')
    spy.mockRestore()
  })

  it('rejects rotate with unsupported alg', async () => {
    const stderr = vi.spyOn(process.stderr, 'write').mockImplementation(() => true)
    const code = await __keys(['rotate', 'ec256'])
    expect(code).toBe(1)
    expect(stderr).toHaveBeenCalled()
    stderr.mockRestore()
  })
})

describe('duck-auth CLI - emit-openapi', () => {
  it('errors when no auth.ts can be found', async () => {
    const stderr = vi.spyOn(process.stderr, 'write').mockImplementation(() => true)
    const dir = mkdtempSync(join(tmpdir(), 'duck-auth-openapi-'))
    const originalCwd = process.cwd()
    try {
      process.chdir(dir)
      const code = await __emitOpenapi([])
      expect(code).toBe(1)
      expect(stderr).toHaveBeenCalled()
    } finally {
      process.chdir(originalCwd)
      rmSync(dir, { recursive: true, force: true })
      stderr.mockRestore()
    }
  })

  it('errors when the provided file does not exist', async () => {
    const stderr = vi.spyOn(process.stderr, 'write').mockImplementation(() => true)
    const code = await __emitOpenapi(['./does-not-exist.ts'])
    expect(code).toBe(1)
    expect(stderr).toHaveBeenCalled()
    stderr.mockRestore()
  })
})
