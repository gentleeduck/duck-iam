# Security Policy

This repository publishes two packages, and this policy covers both:

| Package | Supported |
| --- | --- |
| [`@gentleduck/auth`](https://www.npmjs.com/package/@gentleduck/auth) | the latest minor |
| [`@gentleduck/iam`](https://www.npmjs.com/package/@gentleduck/iam) | the latest minor |

Fixes land on the latest minor. Older minors get no backport, so a security fix is a reason to upgrade
rather than to wait: every release is listed in each package's `CHANGELOG.md`, and anything with a
security consequence says so in its entry.

## Reporting a vulnerability

**[Report it privately through GitHub](https://github.com/gentleeduck/duck-iam/security/advisories/new)**
— the Security tab, "Report a vulnerability". That opens a private thread with the maintainers, keeps the
report attached to the advisory that will eventually credit you, and is the fastest route.

If you would rather use email, **security@gentleduck.org** reaches the same people.

Either way, please do not open a public issue, a discussion, or a pull request that describes the problem
before it is fixed.

Useful in a report, roughly in order of how much it speeds up a fix:

- the package and version you tested (`npm ls @gentleduck/auth`), and the adapter or provider involved
- which of the two it is: something the library does wrong, or something a host using it can do wrong
- a reproduction we can run — a failing test against the package is ideal, a script or a container is fine
- what an attacker gets out of it, and what they need first

## What happens next

We confirm receipt within **48 hours** and tell you whether we can reproduce it, usually in the same reply.

If it is a real defect we write a [GitHub Security Advisory](https://github.com/gentleeduck/duck-iam/security/advisories)
against the affected package, with the version range we have verified rather than only the version you
tested, request a CVE, ship the fix in the next release, and publish the advisory once that release is out.
Publishing is what tells `npm audit` and Dependabot, so consumers find out without reading our changelog.

You are credited in the advisory unless you ask not to be. We ask for **90 days** before public disclosure,
and we would rather publish sooner — the advisory goes out with the release that fixes it.

If we decide something is not a vulnerability, you get the reasoning, not a closed thread. "The host has to
configure it that way" is not on its own a reason: a default that is unsafe, or a misconfiguration the
library accepts quietly, is our bug.

## Scope

In scope: anything in `packages/duck-auth` or `packages/duck-iam` that ships to npm, including the adapters,
the provider implementations, and the framework integrations under `src/server/`.

`@gentleduck/iam/dt` and `./dt/v2` are in scope too. They are meant for development, but they are published
exports, so a panel that renders in production or discloses a policy it should not is a vulnerability here and
not a misuse.

Out of scope, because nothing ships from them: the examples, the documentation sites, and the benchmark and
audit folders. A finding there is an ordinary issue, and still worth filing.
