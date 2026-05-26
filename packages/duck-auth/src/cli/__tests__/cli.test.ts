/**
 * @packageDocumentation
 * @author wildduck2 <https://github.com/gentleeduck/duck-iam>
 */

import { mkdtempSync, readFileSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { __envTemplate, __init, __keys, __scaffoldTemplate, run } from '../index'

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
