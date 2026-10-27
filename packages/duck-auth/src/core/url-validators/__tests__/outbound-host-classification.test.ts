/**
 * The outbound SSRF guard, case by case.
 *
 * `assertSafeOutboundUrl` is the only seam here: it owns the scheme and userinfo
 * rules and then hands the host to a classifier built from `parseIpv4`,
 * `parseIpv6`, `isBlockedIpv4`, `isBlockedIpv6` and `isBlockedHostname`. That
 * classifier is a hand-written IPv6 parser — `::` expansion, an embedded
 * dotted-quad in the last two hextets, zone-id stripping — and before this file
 * one test covered the whole of it, through the name path only.
 *
 * Expected values come from the RFCs named on each case and from the payloads
 * SSRF tooling actually sends, never from re-reading our own range table: a
 * table asserted against itself cannot disagree with a typo in a mask.
 *
 * Scope: spelling only. A name that resolves inward (`127.0.0.1.nip.io`) cannot
 * be caught here and belongs to `assertResolvedHostIsPublic`, which
 * `hostname-blocklist.test.ts` covers.
 */

import { beforeEach, describe, expect, it, vi } from 'vitest'
import { assertResolvedHostIsPublic, assertSafeOutboundUrl } from '../url-validators'

// The production guard; a case about development or test stubs its own environment.
beforeEach(() => {
  vi.stubEnv('NODE_ENV', 'production')
})

/** Whether the guard refuses this host. Uses https, so only the host decides. */
function refuses(host: string): boolean {
  try {
    assertSafeOutboundUrl(`https://${host}/x`, { label: 'probe' })
    return false
  } catch {
    return true
  }
}

const refusedBy = (table: ReadonlyArray<readonly [string, string]>) => table.map(([host, why]) => [host, why] as const)

describe('the SSRF guard refuses addresses that are not publicly routable', () => {
  describe.each(
    refusedBy([
      ['127.0.0.1', 'RFC 1122 loopback'],
      ['127.1.2.3', 'loopback is a /8, not one address'],
      ['0.0.0.0', 'RFC 1122 "this host"; routes to loopback on Linux (Oligo 0.0.0.0 Day)'],
      ['0.1.2.3', '0.0.0.0/8 is a /8'],
      ['10.0.0.1', 'RFC 1918'],
      ['172.16.0.1', 'RFC 1918'],
      ['172.31.255.255', 'RFC 1918, top of the /12'],
      ['192.168.1.1', 'RFC 1918'],
      ['169.254.169.254', 'RFC 3927 link-local: the AWS/Azure/GCP metadata address'],
      ['169.254.0.1', 'link-local is a /16, not one address'],
      ['100.64.0.1', 'RFC 6598 carrier NAT'],
      ['192.0.0.1', 'RFC 6890 IETF protocol assignments'],
      ['198.18.0.1', 'RFC 2544 benchmarking'],
      ['224.0.0.1', 'RFC 5771 multicast'],
      ['255.255.255.255', 'RFC 919 broadcast'],
      ['240.0.0.1', 'RFC 1112 reserved'],
      ['192.0.2.1', 'RFC 5737 TEST-NET-1 documentation'],
      ['198.51.100.1', 'RFC 5737 TEST-NET-2 documentation'],
      ['203.0.113.1', 'RFC 5737 TEST-NET-3 documentation'],
    ]),
  )('%s', (host, why) => {
    it(why, () => {
      expect(refuses(host)).toBe(true)
    })
  })
})

describe('the SSRF guard lets public addresses through', () => {
  /** Over-blocking is the other way to get this wrong: a guard that refuses a
   *  customer's own webhook host is an outage. Each of these sits one address
   *  outside a blocked range. */
  describe.each(
    refusedBy([
      ['8.8.8.8', 'an ordinary public address'],
      ['9.255.255.255', 'one below 10.0.0.0/8'],
      ['11.0.0.0', 'one above 10.0.0.0/8'],
      ['172.15.255.255', 'one below 172.16.0.0/12'],
      ['172.32.0.0', 'one above 172.16.0.0/12'],
      ['192.167.255.255', 'one below 192.168.0.0/16'],
      ['192.169.0.0', 'one above 192.168.0.0/16'],
      ['100.63.255.255', 'one below 100.64.0.0/10'],
      ['100.128.0.0', 'one above 100.64.0.0/10'],
      ['169.253.255.255', 'one below 169.254.0.0/16'],
      ['169.255.0.0', 'one above 169.254.0.0/16'],
      ['192.0.1.1', 'one above the 192.0.0.0/24 assignments block'],
      ['198.20.0.1', 'one above 198.18.0.0/15'],
      ['223.255.255.255', 'one below the 224.0.0.0/4 multicast block'],
      ['192.0.1.1', 'one below TEST-NET-1, which is a /24 and not a /16'],
      ['192.0.3.1', 'one above TEST-NET-1'],
      ['198.52.100.1', 'TEST-NET-2 is 198.51.100.0/24, not 198.0.0.0/8'],
      ['203.1.113.1', 'TEST-NET-3 is 203.0.113.0/24'],
    ]),
  )('%s', (host, why) => {
    it(why, () => {
      expect(refuses(host)).toBe(false)
    })
  })
})

describe('the SSRF guard classifies IPv6, including the forms that tunnel IPv4', () => {
  describe.each(
    refusedBy([
      ['[::1]', 'RFC 4291 loopback'],
      ['[::]', 'RFC 4291 unspecified'],
      ['[fe80::1]', 'RFC 4291 link-local'],
      ['[fc00::1]', 'RFC 4193 unique-local'],
      ['[fd00::1]', 'RFC 4193 unique-local, the half that is actually used'],
      ['[fec0::1]', 'RFC 3879 site-local: deprecated, still routed where configured'],
      ['[ff02::1]', 'RFC 4291 multicast'],
      ['[100::1]', 'RFC 6666 discard-only'],
      ['[::ffff:127.0.0.1]', 'RFC 4291 IPv4-mapped loopback'],
      ['[::ffff:169.254.169.254]', 'IPv4-mapped metadata: the classic v6 SSRF bypass'],
      ['[::ffff:a9fe:a9fe]', 'the same address written in hex, which is the spelling that arrives'],
      ['[::127.0.0.1]', 'RFC 4291 s2.5.5.1 IPv4-compatible, deprecated'],
      ['[64:ff9b::169.254.169.254]', 'RFC 6052 NAT64 carrying metadata'],
      ['[64:ff9b:1::1]', 'RFC 8215 local-use translation'],
      ['[2002::1]', 'RFC 3056 6to4'],
      ['[2001::1]', 'RFC 4380 Teredo'],
      ['[2001:2::1]', 'RFC 5180 benchmarking'],
      ['[2001:db8::1]', 'RFC 3849 documentation'],
      ['[3fff::1]', 'RFC 9637 documentation'],
      ['[3fff:fff::1]', 'RFC 9637 is a /20, so the whole top nibble of the second hextet is in it'],
      ['[5f00::1]', 'RFC 9602 SRv6 segment identifiers'],
    ]),
  )('%s', (host, why) => {
    it(why, () => {
      expect(refuses(host)).toBe(true)
    })
  })

  it('lets a public IPv6 address through', () => {
    expect(refuses('[2606:4700:4700::1111]')).toBe(false)
    expect(refuses('[2001:4860:4860::8888]')).toBe(false)
  })

  it('does not mistake a public 2001::/16 address for Teredo, which is 2001::/32', () => {
    // Teredo needs the second hextet zero; Google's resolver has 0x4860 there.
    expect(refuses('[2001:4860::1]')).toBe(false)
  })

  /** Each of these sits just outside one of the IANA special-purpose blocks. The
   *  3fff cases are here because a /20 written as a 12-bit mask also swallowed
   *  3ffe::/16, the returned 6bone range, which is ordinary address space now. */
  it('keeps addresses just outside the IANA special-purpose blocks public', () => {
    for (const host of ['[3ffe::1]', '[3ffd::1]', '[3fff:1000::1]', '[4000::1]', '[2001:3::1]', '[5e00::1]']) {
      expect(refuses(host), host).toBe(false)
    }
  })

  it('expands :: in any position', () => {
    expect(refuses('[fe80:0:0:0:0:0:0:1]')).toBe(true)
    expect(refuses('[0:0:0:0:0:0:0:1]')).toBe(true)
  })
})

describe('the SSRF guard refuses internal hosts reached by name', () => {
  describe.each(
    refusedBy([
      ['localhost', 'the name'],
      ['LOCALHOST', 'the name, shouted: classification is case-insensitive'],
      ['localhost.localdomain', 'the RHEL-family /etc/hosts spelling'],
      ['ip6-localhost', 'the Debian-family /etc/hosts spelling'],
      ['ip6-loopback', 'the other Debian-family spelling'],
      ['localhost6', 'the RHEL-family v6 spelling'],
      ['metadata.google.internal', 'how GCP metadata is actually reached'],
      ['metadata.google.internal.', 'RFC 1034 absolute form: the trailing dot must not evade it'],
      ['metadata.goog', "GCP's public alias for the same server"],
      ['anything.internal', 'ICANN-reserved for private use'],
      ['printer.local', 'RFC 6762 mDNS'],
      ['evil.example.localhost', 'RFC 6761: everything under .localhost is loopback'],
    ]),
  )('%s', (host, why) => {
    it(why, () => {
      expect(refuses(host)).toBe(true)
    })
  })

  describe.each(
    refusedBy([
      ['example.com', 'an ordinary name'],
      ['notlocalhost.com', 'contains "localhost" but is not under it'],
      ['localhost.evil.com', 'starts with "localhost": a public name an attacker can register'],
      ['my-local.com', 'ends in "local" without the dot'],
      ['internal.example.com', 'starts with "internal"'],
      ['metadata.goog.evil.com', 'starts with the metadata alias'],
      ['api.internal.example.com', 'carries ".internal" inside it: a suffix rule must not match there'],
      ['svc.local.example.com', 'carries ".local" inside it'],
      ['app.localhost.example.com', 'carries ".localhost" inside it'],
    ]),
  )('%s', (host, why) => {
    it(`is allowed: ${why}`, () => {
      expect(refuses(host)).toBe(false)
    })
  })
})

describe('assertResolvedHostIsPublic classifies a raw address, with no URL to normalise it', () => {
  /**
   * The other seam, and a different input alphabet. `assertSafeOutboundUrl` gets
   * its host from `new URL`, which canonicalises first — it rewrites
   * `::ffff:169.254.169.254` to `::ffff:a9fe:a9fe` and rejects a bracketed zone
   * id outright. A resolver hands this function the address as text, unbracketed
   * and possibly scoped, so `parseIpv6`'s own normalisation is load-bearing here
   * and nowhere else.
   */
  const refusesAddress = (address: string): boolean => {
    try {
      assertResolvedHostIsPublic(address, 'probe')
      return false
    } catch {
      return true
    }
  }

  it('strips a zone identifier, which a link-local answer carries', () => {
    expect(refusesAddress('fe80::1%eth0')).toBe(true)
    expect(refusesAddress('fe80::1%25eth0')).toBe(true)
  })

  it('classifies an unbracketed v6 address', () => {
    expect(refusesAddress('::1')).toBe(true)
    expect(refusesAddress('2606:4700:4700::1111')).toBe(false)
  })

  it('classifies the dotted-quad spelling of an IPv4-mapped address', () => {
    // No URL ran, so this reaches parseIpv6's embedded-dotted-quad branch as written.
    expect(refusesAddress('::ffff:169.254.169.254')).toBe(true)
    expect(refusesAddress('::ffff:127.0.0.1')).toBe(true)
  })

  it('classifies a plain v4 answer', () => {
    expect(refusesAddress('169.254.169.254')).toBe(true)
    expect(refusesAddress('8.8.8.8')).toBe(false)
  })
})

describe('the SSRF guard rules that are not about the host', () => {
  it('refuses plain http in production and admits it outside', () => {
    expect(refuses('example.com')).toBe(false)
    expect(() => assertSafeOutboundUrl('http://example.com/x', { label: 'probe' })).toThrow()
    expect(() => assertSafeOutboundUrl('ftp://example.com/x', { label: 'probe' })).toThrow()
    vi.stubEnv('NODE_ENV', 'development')
    expect(() => assertSafeOutboundUrl('http://example.com/x', { label: 'probe' })).not.toThrow()
    expect(() => assertSafeOutboundUrl('ftp://example.com/x', { label: 'probe' })).toThrow()
  })

  it('refuses loopback in production', () => {
    for (const url of ['https://127.0.0.1/x', 'https://localhost/x', 'https://[::1]/x']) {
      expect(() => assertSafeOutboundUrl(url, { label: 'probe' })).toThrow()
    }
    expect(() => assertResolvedHostIsPublic('127.0.0.1', 'probe')).toThrow()
  })

  // A receiver on this machine is what a dev server delivers to.
  it.each(['development', 'test'])('admits loopback under NODE_ENV=%s', (env) => {
    vi.stubEnv('NODE_ENV', env)
    for (const url of ['http://127.0.0.1/x', 'http://localhost/x', 'http://[::1]/x']) {
      expect(() => assertSafeOutboundUrl(url, { label: 'probe' })).not.toThrow()
    }
    expect(() => assertResolvedHostIsPublic('127.0.0.1', 'probe')).not.toThrow()
  })

  it.each(['development', 'test'])('still refuses every other blocked host under NODE_ENV=%s', (env) => {
    vi.stubEnv('NODE_ENV', env)
    for (const url of ['http://169.254.169.254/x', 'http://10.0.0.1/x', 'http://[::2]/x']) {
      expect(() => assertSafeOutboundUrl(url, { label: 'probe' })).toThrow()
    }
    expect(() => assertResolvedHostIsPublic('10.0.0.1', 'probe')).toThrow()
  })

  it('refuses credentials in the URL, which leak to every proxy and access log on the path', () => {
    expect(() => assertSafeOutboundUrl('https://user:pw@example.com/x', { label: 'probe' })).toThrow()
    expect(() => assertSafeOutboundUrl('https://user@example.com/x', { label: 'probe' })).toThrow()
  })

  it('refuses a string that is not a URL at all', () => {
    for (const bad of ['', 'not-a-url', 'https://', '//example.com/x']) {
      expect(() => assertSafeOutboundUrl(bad, { label: 'probe' })).toThrow()
    }
  })

  it('refuses a bracketed zone id, which WHATWG URL has no syntax for', () => {
    // Fails closed as a parse error rather than as a host refusal, so it never
    // reaches the classifier. The resolved-address seam above is where the zone
    // strip is exercised.
    expect(() => assertSafeOutboundUrl('https://[fe80::1%25eth0]/x', { label: 'probe' })).toThrow()
  })
})
