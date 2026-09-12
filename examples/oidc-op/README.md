# OIDC OP example

Minimal end-to-end OAuth2/OIDC OP wired up with `@gentleduck/auth/oidc/op`.

Run it with Bun: `server.ts` is TypeScript, and the `dev` script is
`bun run server.ts`. It talks to no external services and imports only
`node:http` and `node:crypto` beyond `@gentleduck/auth`.

State is held in memory - the default `MemoryClientStore` / `MemoryCodeStore`
and friends ship with the `oidc/op` subpath. Swap them for the Drizzle ports
under `@gentleduck/auth/oidc/op/drizzle/{pg,sqlite,mysql}` to wire a real
database.

## Run it

```bash
bun install
bun run server.ts
```

Server listens on `http://localhost:8787`. Routes:

- `GET /authorize?...` - OIDC authorize. With no session, you see the
  fake-login screen. With a session, you see the consent screen.
- `POST /login` - fake login button. Creates a session for `user@example.com`.
- `POST /consent` - "Allow" button on the consent screen. The "Deny" button
  posts to `/deny`, which this server does not implement; it answers 404.
- `POST /token` - OAuth2 token endpoint. Exchanges code+PKCE for tokens.
- `GET /userinfo` - bearer-protected claims.
- `POST /introspect` - RFC 7662 introspection (basic auth).
- `POST /revoke` - RFC 7009 revocation.

## End-to-end smoke run

Pre-registered client `demo-spa` has `redirect_uri = http://localhost:8787/callback`
and `token_endpoint_auth_method: 'none'`. There is no bundled CLI client; drive
the flow in a browser.

1. Generate a PKCE pair and open `/authorize` with it:

   ```
   http://localhost:8787/authorize
     ?client_id=demo-spa
     &redirect_uri=http://localhost:8787/callback
     &response_type=code
     &scope=openid%20profile%20email
     &state=<state>
     &code_challenge=<S256 of your verifier>
     &code_challenge_method=S256
   ```

2. Click through the fake-login screen (signs you in as `user@example.com`)
   and then "Allow" on the consent screen.
3. The browser lands on `/callback?code=…`, which this server does not
   handle - copy the `code` out of the address bar.
4. Exchange it, unauthenticated, because the client is public:

   ```bash
   curl -s http://localhost:8787/token \
     -d grant_type=authorization_code \
     -d client_id=demo-spa \
     -d redirect_uri=http://localhost:8787/callback \
     -d code=<code> \
     -d code_verifier=<verifier>
   ```

5. Call `/userinfo` with the returned `access_token` as a bearer token.

The `id_token` is signed HS256 with a demo secret from `server.ts`. It is a
fixture, not a key you should reuse.
