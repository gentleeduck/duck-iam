/** Host classification for the outbound SSRF guard. */

/** RFC 1918, RFC 6598, RFC 5735 and the ranges that are not routable on the public internet. */
const V4_BLOCKED: Array<{ mask: number; net: number }> = [
  { mask: 0xff000000, net: 0x00000000 }, // 0.0.0.0/8 this network
  { mask: 0xff000000, net: 0x0a000000 }, // 10.0.0.0/8
  { mask: 0xffc00000, net: 0x64400000 }, // 100.64.0.0/10 cgnat
  { mask: 0xff000000, net: 0x7f000000 }, // 127.0.0.0/8 loopback
  { mask: 0xffff0000, net: 0xa9fe0000 }, // 169.254.0.0/16 link-local, incl. 169.254.169.254
  { mask: 0xfff00000, net: 0xac100000 }, // 172.16.0.0/12
  { mask: 0xffffff00, net: 0xc0000000 }, // 192.0.0.0/24 ietf protocol assignments
  { mask: 0xffff0000, net: 0xc0a80000 }, // 192.168.0.0/16
  { mask: 0xfffe0000, net: 0xc6120000 }, // 198.18.0.0/15 benchmarking
  { mask: 0xf0000000, net: 0xe0000000 }, // 224.0.0.0/4 multicast
  { mask: 0xf0000000, net: 0xf0000000 }, // 240.0.0.0/4 reserved, incl. 255.255.255.255
]

/** Parse a dotted-quad into a 32-bit number, or null when the string is not one. */
export function parseIpv4(host: string): number | null {
  const parts = host.split('.')
  if (parts.length !== 4) return null
  let value = 0
  for (const part of parts) {
    if (part.length === 0 || part.length > 3 || !/^[0-9]+$/.test(part)) return null
    const octet = Number(part)
    if (octet > 255) return null
    value = value * 256 + octet
  }
  return value >>> 0
}

/** Parse an ipv6 literal, with or without brackets, into its eight hextets. */
export function parseIpv6(host: string): number[] | null {
  let text = host
  if (text.startsWith('[') && text.endsWith(']')) text = text.slice(1, -1)
  const zone = text.indexOf('%')
  if (zone !== -1) text = text.slice(0, zone)
  if (!text.includes(':')) return null

  const [head, tail, ...rest] = text.split('::')
  if (rest.length > 0 || head === undefined) return null

  const expand = (group: string): number[] | null => {
    if (group === '') return []
    const out: number[] = []
    const pieces = group.split(':')
    for (let i = 0; i < pieces.length; i++) {
      const piece = pieces[i] as string
      // A trailing dotted-quad occupies the last two hextets (`::ffff:1.2.3.4`).
      if (i === pieces.length - 1 && piece.includes('.')) {
        const v4 = parseIpv4(piece)
        if (v4 === null) return null
        out.push(v4 >>> 16, v4 & 0xffff)
        continue
      }
      if (!/^[0-9a-f]{1,4}$/i.test(piece)) return null
      out.push(Number.parseInt(piece, 16))
    }
    return out
  }

  const left = expand(head)
  const right = tail === undefined ? [] : expand(tail)
  if (left === null || right === null) return null
  if (tail === undefined) return left.length === 8 ? left : null
  const gap = 8 - left.length - right.length
  if (gap < 1) return null
  return [...left, ...Array.from({ length: gap }, () => 0), ...right]
}

/** Whether a parsed ipv4 address is somewhere a webhook must never be sent. */
export function isBlockedIpv4(value: number): boolean {
  return V4_BLOCKED.some((range) => (value & range.mask) >>> 0 === range.net)
}

/** Whether parsed hextets name an address a webhook must never be sent to. */
export function isBlockedIpv6(h: number[]): boolean {
  const [h0 = 0, h1 = 0, h2 = 0, h3 = 0, h4 = 0, h5 = 0] = h
  if (h.every((x) => x === 0)) return true // ::
  if (h0 === 0 && h1 === 0 && h2 === 0 && h3 === 0 && h4 === 0 && h5 === 0) return true // ::1 and ::a.b.c.d
  if (h0 === 0 && h1 === 0 && h2 === 0 && h3 === 0 && h4 === 0 && h5 === 0xffff) return true // ::ffff:0:0/96
  if ((h0 & 0xfe00) === 0xfc00) return true // fc00::/7 unique-local
  if ((h0 & 0xffc0) === 0xfe80) return true // fe80::/10 link-local
  if ((h0 & 0xff00) === 0xff00) return true // ff00::/8 multicast
  if (h0 === 0x0100 && h1 === 0 && h2 === 0 && h3 === 0) return true // 100::/64 discard-only
  if (h0 === 0x0064 && h1 === 0xff9b) return true // 64:ff9b::/32 nat64
  if (h0 === 0x2002) return true // 2002::/16 6to4
  if (h0 === 0x2001 && h1 === 0x0000) return true // 2001::/32 teredo
  return false
}

/** Loopback and the cloud metadata endpoint under a name rather than an address. The `localhost` aliases
 *  ship in the /etc/hosts of Debian-family images; `metadata.goog` is the public alias of GCP's metadata
 *  server, which the v4 list already refuses at 169.254.169.254 but which is reached by name. */
const BLOCKED_NAMES = new Set([
  'internal',
  'ip6-localhost',
  'ip6-loopback',
  'local',
  'localhost',
  'localhost4',
  'localhost6',
  'metadata.goog',
])

/** `.internal` is ICANN-reserved for private use, so nothing under it is publicly routable, and it is
 *  where `metadata.google.internal` answers. */
const BLOCKED_SUFFIXES = ['.internal', '.local', '.localhost', '.metadata.goog']

/** Names that resolve inside the host or the local network by definition. */
export function isBlockedHostname(host: string): boolean {
  const name = host.endsWith('.') ? host.slice(0, -1) : host
  return BLOCKED_NAMES.has(name) || BLOCKED_SUFFIXES.some((suffix) => name.endsWith(suffix))
}
