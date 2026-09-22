/**
 * The v4 block list goes out of its way to name the cloud metadata endpoint — `169.254.0.0/16
 * link-local, incl. 169.254.169.254` — so refusing metadata is a stated intent of this guard. The
 * *name* path did not implement it: `isBlockedHostname` knew four spellings of "localhost" and nothing
 * else, and `metadata.google.internal`, which is how GCP's metadata server is actually reached and what
 * every SSRF payload targeting GCP uses, passed.
 *
 * The loopback aliases are the same shape: `localhost6` and `ip6-localhost` are in the `/etc/hosts` that
 * ships on Debian-family images, which is most containers this library runs in.
 *
 * The DNS-resolution cases are deliberately absent. A wildcard resolver like `127.0.0.1.nip.io` cannot be
 * caught by spelling, and `assertResolvedHostIsPublic` is the layer that exists for it.
 */
import { describe, expect, it } from 'vitest'
import { assertSafeOutboundUrl } from '../url-validators'

const refuses = (host: string): boolean => {
  try {
    assertSafeOutboundUrl(`https://${host}/x`, { label: 'probe' })
    return false
  } catch {
    return true
  }
}

describe('the outbound host guard refuses internal names, not only internal addresses', () => {
  it.each(['metadata.google.internal', 'metadata.goog', 'instance.c.proj.internal', 'internal'])(
    'refuses %s',
    (host) => {
      expect(refuses(host)).toBe(true)
    },
  )

  it.each(['localhost6', 'localhost4', 'ip6-localhost', 'ip6-loopback'])(
    'refuses the /etc/hosts loopback alias %s',
    (host) => {
      expect(refuses(host)).toBe(true)
    },
  )

  it.each(['localhost', 'LOCALHOST', 'localhost.', 'x.localhost', 'local', 'printer.local'])(
    'still refuses %s',
    (host) => {
      expect(refuses(host)).toBe(true)
    },
  )

  it.each(['169.254.169.254', '127.0.0.1', '0177.0.0.1', '2130706433', '[::1]', '[::ffff:127.0.0.1]'])(
    'still refuses the address form %s',
    (host) => {
      expect(refuses(host)).toBe(true)
    },
  )

  it.each(['example.com', 'hooks.slack.com', 'fcm.googleapis.com', 'metadata.example.com', 'internalise.com'])(
    'still allows %s',
    (host) => {
      expect(refuses(host)).toBe(false)
    },
  )

  it('leaves a name that only resolves inward to the resolution guard', () => {
    // Spelling says nothing about where this points; `assertResolvedHostIsPublic` is the layer for it.
    expect(refuses('127.0.0.1.nip.io')).toBe(false)
  })
})
