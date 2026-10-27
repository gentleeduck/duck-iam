# Security advisories — maintainer runbook

The public half is `SECURITY.md`. This is how a report becomes a published advisory.

## Repository settings

**Settings → Code security**, all on:

- **Private vulnerability reporting** — what puts "Report a vulnerability" on the Security tab
- **Dependabot alerts** and **Dependabot security updates**
- **Secret scanning** and **Push protection**

## When a report arrives

1. **Within 48 hours**, reply on the advisory thread and accept the report, which moves it from triage to a
   draft:
   `gh api --method PATCH repos/gentleeduck/duck-iam/security-advisories/<GHSA> -f state=draft`
2. **Reproduce it against the latest release**, not only the version reported. A report against an old
   version may already be fixed — and then the question is *where*, which is the next section.
3. **Fix an open one in the advisory's temporary private fork** (the advisory's page, "Start a temporary
   private fork"), so the fix is not public before the release that ships it.

## Find the real range

The range is a claim about what consumers installed, so read it off the published tarballs, not git
history. A commit can sit on `main` for days before a release carries it, and npm skips numbers: there is no
`@gentleduck/auth` 5.15.0 and no `@gentleduck/iam` 2.1.0.

```sh
bun run advisory:probe -- @gentleduck/auth 'aal: 2' dist/providers/saml
bun run advisory:probe -- @gentleduck/iam 'x-user-id' dist 1.1.1 2.0.1 3.0.1
```

Probe once for a string only the vulnerable code has and once for one only the fix has. The range ends where
they swap. It covers everything affected **under the default configuration**, which can end later than the
fix the reporter has in mind: GHSA-5h9c-2cgg-j467's hard-coded `aal: 2` ended at 5.9.0, but the default set
still counted single-factor contexts until 5.17.0, so the range is `< 5.17.0`.

## Write it

- **One advisory per reported vulnerability.** For an audit batch, one per release, organised by what an
  attacker gets, which is the same rule `.changeset/` follows.
- **Summary:** what an attacker gets, with the package name in it.
- **Range** `< <patched>`, **patched version**, **CWEs**, **severity**. Give a CVSS vector only if you scored
  one; severity alone is better than a vector nobody computed.
- **Description:** Summary, Details, Affected versions, Patch, Workaround. Name the precondition — the adapter,
  the provider, the config — so a consumer can tell whether it applies to them.
- **A reporter's text stays as written.** Add a "Maintainer response" section below it, and credit them.

## Publish

- **Only once the patched version is on npm** (`npm view <package>@<version> version`). Publishing before
  then announces an open hole.
- **Request a CVE** as you publish: the advisory's "Request CVE" button, or
  `gh api --method POST repos/gentleeduck/duck-iam/security-advisories/<GHSA>/cve`.
- Publishing is what reaches `npm audit` and Dependabot, so consumers hear without reading a changelog.
- **It is permanent.** GitHub can withdraw an advisory, which is itself public, but cannot unpublish one.

## Advisories

Each published with a CVE requested from GitHub: the first six on 2026-10-25, GHSA-x3jh-hfw7-qxvf on 2026-10-27.

| Advisory | Package | Range | Severity | State |
| --- | --- | --- | --- | --- |
| [GHSA-x3jh-hfw7-qxvf](https://github.com/gentleeduck/duck-iam/security/advisories/GHSA-x3jh-hfw7-qxvf) | `@gentleduck/auth` | `< 5.18.0` | high | published |
| [GHSA-5h9c-2cgg-j467](https://github.com/gentleeduck/duck-iam/security/advisories/GHSA-5h9c-2cgg-j467) | `@gentleduck/auth` | `< 5.17.0` | high | published, reported by EQSTLab |
| [GHSA-r79m-2rfh-7rgf](https://github.com/gentleeduck/duck-iam/security/advisories/GHSA-r79m-2rfh-7rgf) | `@gentleduck/auth` | `< 5.17.0` | high | published |
| [GHSA-g5qq-cw3q-85c6](https://github.com/gentleeduck/duck-iam/security/advisories/GHSA-g5qq-cw3q-85c6) | `@gentleduck/auth` | `< 5.14.0` | critical | published |
| [GHSA-jvxv-xjr4-73p2](https://github.com/gentleeduck/duck-iam/security/advisories/GHSA-jvxv-xjr4-73p2) | `@gentleduck/iam` | `< 5.12.0` | high | published |
| [GHSA-qx7x-27h5-xv9r](https://github.com/gentleeduck/duck-iam/security/advisories/GHSA-qx7x-27h5-xv9r) | `@gentleduck/iam` | `< 5.11.0` | high | published |
| [GHSA-qxwf-fhgx-6fc9](https://github.com/gentleeduck/duck-iam/security/advisories/GHSA-qxwf-fhgx-6fc9) | `@gentleduck/iam` | `< 3.0.1` | critical | published |
