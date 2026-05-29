# OIDC OP example

Minimal end-to-end OAuth2/OIDC OP wired up with `@gentleduck/auth/oidc/op`.

Runs on Node 20+ with no external services. State is held in memory (the
default `MemoryClientStore` / `MemoryCodeStore` / etc. ship with the
`oidc/op` subpath). Swap them for the Drizzle ports under
`@gentleduck/auth/oidc/op/drizzle/{pg,sqlite,mysql}` to wire a real database.

## Run it

```bash
bun install
bun run server.ts
```

Server listens on `http://localhost:8787`. Routes:

- `GET /authorize?...` - OIDC authorize. With no session, you see the
  fake-login screen. With a session, you see the consent screen.
- `POST /login` - fake login button. Creates a session for `user@example.com`.
- `POST /consent` - "Allow" button on the consent screen.
- `POST /token` - OAuth2 token endpoint. Exchanges code+PKCE for tokens.
- `GET /userinfo` - bearer-protected claims.
- `POST /introspect` - RFC 7662 introspection (basic auth).
- `POST /revoke` - RFC 7009 revocation.

## End-to-end smoke run

Pre-registered client `demo-spa` has `redirect_uri = http://localhost:8787/callback`
and `token_endpoint_auth_method: 'none'`. Use the bundled CLI flow:

```bash
bun run client.ts
```

The script generates a PKCE pair, opens `/authorize`, completes login +
consent on your behalf via cookies, exchanges the code at `/token`, and
prints the parsed `id_token` payload + `/userinfo` response.
