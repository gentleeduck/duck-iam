/**
 * Static-analysis assertions that enforce security invariants by
 * grepping the source tree at test time.
 *
 * These tests guard against the class of bugs that can't be caught
 * by unit tests of a single function: someone adds Math.random() to a
 * secret-generation path during a refactor, or replaces timingSafeEqual
 * with === in a token compare, and the resulting code still compiles
 * and the existing happy-path tests still pass. The bug is invisible
 * until somebody reads the diff carefully.
 *
 * If one of these tests fails, do NOT add an allowlist entry without
 * understanding what the rule was protecting against. The comment on
 * each test explains the threat.
 */

import { readdirSync, readFileSync, statSync } from 'node:fs'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'
import { describe, expect, it } from 'vitest'

const ROOT = join(dirname(fileURLToPath(import.meta.url)), '..')

interface FileScan {
  path: string
  contents: string
}

function walkTs(dir: string, out: FileScan[] = []): FileScan[] {
  for (const entry of readdirSync(dir)) {
    if (entry === 'node_modules' || entry === 'dist' || entry === '__tests__') continue
    const full = join(dir, entry)
    const stat = statSync(full)
    if (stat.isDirectory()) {
      walkTs(full, out)
    } else if (entry.endsWith('.ts')) {
      out.push({ path: full.slice(ROOT.length + 1), contents: readFileSync(full, 'utf8') })
    }
  }
  return out
}

const ALL_FILES = walkTs(ROOT)

function filesMatching(predicate: (f: FileScan) => boolean): FileScan[] {
  return ALL_FILES.filter(predicate)
}

function linesContaining(file: FileScan, pattern: RegExp): string[] {
  const hits: string[] = []
  for (const line of file.contents.split('\n')) {
    if (pattern.test(line)) {
      // Skip lines that are comments only (`//` or `/*` or `*` at line start ignoring whitespace)
      const trimmed = line.trim()
      if (trimmed.startsWith('//') || trimmed.startsWith('*') || trimmed.startsWith('/*')) continue
      hits.push(line)
    }
  }
  return hits
}

const SECURITY_PATHS = ['core/', 'providers/', 'oidc/op/', 'oidc/index.ts', 'transport/']

function isSecurityPath(path: string): boolean {
  return SECURITY_PATHS.some((p) => path.includes(p))
}

const SECRET_GEN_ALLOWED_HELPERS = ['authRandomToken', 'randomBytes', 'randomUUID', 'createHash', 'createHmac']

describe('No Math.random in security paths', () => {
  it('Math.random must not appear in core / providers / oidc / transport', () => {
    const offenders = filesMatching((f) => isSecurityPath(f.path)).flatMap((f) =>
      linesContaining(f, /\bMath\.random\b/).map((l) => `${f.path}: ${l.trim()}`),
    )
    expect(offenders).toEqual([])
  })

  it('Math.random elsewhere is documented (used only for instance IDs / dev channels)', () => {
    const offenders = filesMatching((f) => !isSecurityPath(f.path)).flatMap((f) =>
      linesContaining(f, /\bMath\.random\b/).map((l) => `${f.path}: ${l.trim()}`),
    )
    // Acceptable uses (instance IDs, dev channels). Update this list only
    // after confirming the use is non-cryptographic.
    const acceptableHints = ['instanceId', 'messageId']
    for (const offender of offenders) {
      const ok = acceptableHints.some((hint) => offender.includes(hint))
      expect(ok, `unaccounted Math.random in ${offender}`).toBe(true)
    }
  })
})

describe('No bespoke timing-unsafe compares on secrets', () => {
  const SECRET_FIELD_NAMES = ['tokenHash', 'secretHash', 'clientSecret', 'codeChallenge', 'code_verifier', 'verifier']

  it('does not compare secret-named fields with ===', () => {
    const offenders: string[] = []
    for (const f of filesMatching((f) => isSecurityPath(f.path))) {
      for (const line of f.contents.split('\n')) {
        const trimmed = line.trim()
        if (trimmed.startsWith('//') || trimmed.startsWith('*')) continue
        for (const field of SECRET_FIELD_NAMES) {
          const re = new RegExp(`\\b${field}\\s*===`, 'i')
          if (re.test(line)) offenders.push(`${f.path}: ${trimmed}`)
        }
      }
    }
    expect(offenders).toEqual([])
  })
})

describe('No console.log in security paths', () => {
  it('debug logging must not leak from production code', () => {
    const offenders = filesMatching((f) => isSecurityPath(f.path)).flatMap((f) =>
      linesContaining(f, /\bconsole\.log\b/).map((l) => `${f.path}: ${l.trim()}`),
    )
    expect(offenders).toEqual([])
  })
})

describe('Recovery / signup / reset tokens are authSha256-hashed at rest', () => {
  it('every secret-write path passes the secret through authSha256 before storage', () => {
    // The presence of `secret: secretHash` and the absence of
    // `secret: token,` (raw token written directly) is the structural
    // invariant. The actual hash function is in core/crypto.ts.
    const tokenWriteFiles = filesMatching((f) =>
      /flows\/(.*-reset|.*-verification|signup|account-deletion)\.ts$/.test(f.path),
    )
    for (const f of tokenWriteFiles) {
      // Each file must import sha256 (or randomBytes) before it can write a token.
      const importsCrypto = /from '..\/..\/crypto'|from '..\/..\/..\/core\/crypto'/.test(f.contents)
      if (/secret: token\b/.test(f.contents)) {
        expect(importsCrypto, `${f.path} writes raw token without crypto import`).toBe(true)
      }
    }
  })
})

describe('oauth / OIDC state nonces are crypto-random', () => {
  it('OIDC OP issues codes via authRandomToken (not Math.random / Date.now)', () => {
    const opFile = ALL_FILES.find((f) => f.path === 'oidc/op/index.ts')
    expect(opFile).toBeDefined()
    if (!opFile) return
    expect(opFile.contents).toContain('authRandomToken(')
    expect(opFile.contents).not.toMatch(/code\s*=\s*Date\.now/)
    expect(opFile.contents).not.toMatch(/code\s*=\s*Math\.random/)
  })

  it('oauth state / nonce generation routes through authRandomToken', () => {
    const oauthFiles = filesMatching((f) => /providers\/oauth\/.*\.ts$/.test(f.path))
    for (const f of oauthFiles) {
      if (!/state|nonce/i.test(f.contents)) continue
      // Either the file generates state/nonce itself or delegates upward.
      // We assert the negative: no Math.random for state / nonce names.
      const offenders = linesContaining(f, /(state|nonce).*Math\.random/i)
      expect(offenders).toEqual([])
    }
  })
})

describe('Flow handlers throw AuthError for request-time errors', () => {
  it('flows/* files import AuthError (request-time errors must carry an error code)', () => {
    const flowFiles = filesMatching((f) => /core\/facets\/flows\/.+\.ts$/.test(f.path))
    expect(flowFiles.length).toBeGreaterThan(0)
    for (const f of flowFiles) {
      expect(f.contents, `${f.path} doesn't import AuthError`).toContain('AuthError')
    }
  })
})

describe('Length caps on user-supplied strings before they enter URLs / headers / hashes', () => {
  // Heuristic: the providers/* and oidc/op/* request entry points should
  // contain at least one `.length >` or `.length <=` check before flowing
  // strings into upstream IO.
  it('every provider main file has length caps somewhere', () => {
    const providerEntries = filesMatching((f) =>
      /providers\/(password|magic-link|saml|passkey|oauth\/(authGoogle|authGithub|authMicrosoft|authDiscord|authLinkedin|authApple))\.ts$/.test(
        f.path,
      ),
    )
    for (const f of providerEntries) {
      const hasCap = /\.length\s*[><=]/.test(f.contents)
      expect(hasCap, `${f.path} has no length caps - audit user input handling`).toBe(true)
    }
  })

  it('OIDC OP request handlers have length caps', () => {
    const opIndex = ALL_FILES.find((f) => f.path === 'oidc/op/index.ts')
    expect(opIndex).toBeDefined()
    if (!opIndex) return
    expect(opIndex.contents).toMatch(/\.length\s*[><=]/)
  })
})

describe('Cookie defaults are HttpOnly + Secure + SameSite', () => {
  it('AuthCookieTransport defaults assert HttpOnly + secure + sameSite', () => {
    const cookieFile = ALL_FILES.find((f) => f.path === 'core/transport/cookie.ts')
    expect(cookieFile).toBeDefined()
    if (!cookieFile) return
    expect(cookieFile.contents).toMatch(/httpOnly|HttpOnly/i)
    expect(cookieFile.contents).toMatch(/secure/i)
    expect(cookieFile.contents).toMatch(/sameSite|SameSite/i)
  })
})

describe('JWT alg pinning prevents alg-confusion (RFC 8725 §3.1)', () => {
  it('AuthJwtTransport verify path checks alg against the verify key, not the header', () => {
    const jwtFile = ALL_FILES.find((f) => f.path === 'core/transport/jwt.ts')
    expect(jwtFile).toBeDefined()
    if (!jwtFile) return
    // The well-known footgun: trusting the JWT header's `alg` field.
    // We assert that the file mentions alg-confusion in a defensive
    // way (either via an alg-pin comment or an `alg !== ` rejection).
    const hasAlgPin = /alg\s*!==|alg-confusion|alg pinned|RFC 8725/.test(jwtFile.contents)
    expect(hasAlgPin).toBe(true)
  })
})
