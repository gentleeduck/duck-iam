---
'@gentleduck/iam': minor
---

**The HTTP adapter refuses every IP literal outside the public internet as its `baseUrl`.** Its SSRF guard knew
loopback, RFC 1918, link-local and unique-local, and let the other non-public ranges through: CGNAT
`100.64.0.0/10`, where `100.100.100.200` is Alibaba Cloud's metadata server, site-local `fec0::/10`, multicast, and
the reserved, benchmarking and documentation ranges. The SIIT form `::ffff:0:a.b.c.d` went past its IPv4 unwrapping
as well, so `http://[::ffff:0:7f00:1]` reached `127.0.0.1`. Literals are now classified by the same table
`@gentleduck/auth`'s outbound guard uses.

**Breaking: an IPv6 address that carries an IPv4 is refused, whatever IPv4 it carries.** A mapped, compatible, 6to4
or NAT64 address was judged by the IPv4 inside it, so one carrying a public address passed, and a SIIT or Teredo
address passed unexamined. Each is now refused whole, so no unwrapping can miss a private address inside one. Write
the IPv4 itself, or set `allowPrivateHosts: true`.

Names are still not checked: a `baseUrl` of `localhost` or `metadata.google.internal` passes the guard as before.
Constrain them with `allowedHosts`.
