# OIDC OP example

An OpenID provider on `@gentleduck/auth/oidc/op`, with a demo sign-in and a consent page.

One file, one port, everything in memory: the engine runs on the memory adapter, and the OP on its
default memory stores, both of which production refuses, so `bun run dev` sets `NODE_ENV=development`.
For a database, pass the Drizzle stores from
`@gentleduck/auth/oidc/op/drizzle/{pg,sqlite,mysql}` to `createOidcOP` as `stores`.

## Run it

```bash
bun install
bun run dev
```

It listens on `http://localhost:8787`; set `PORT` to move it. Routes:

- `GET /authorize` - the authorize endpoint. With no session you see the demo sign-in, then the
  consent screen.
- `POST /login` - the demo sign-in, as `user@example.com`. It sends you back to the authorize request
  without `login` in `prompt` and without `max_age`, which the sign-in answered.
- `POST /consent` - Allow or Deny. Deny sends `error=access_denied` to the client.
- `POST /token` - the token endpoint: a code with its PKCE verifier, or a refresh token.
- `GET /userinfo` - the claims for a bearer access token.
- `POST /introspect` - RFC 7662, for a confidential client.
- `POST /revoke` - RFC 7009. A client authenticates as it does at `/token`, so the public demo client
  names itself with `client_id`.

`/login` and `/consent` refuse a post from another origin.

## A sign-in, end to end

The pre-registered client `demo-spa` is public (`token_endpoint_auth_method: 'none'`) and redirects to
`http://localhost:8787/callback`. There is no bundled client; drive the flow in a browser.

1. Make a PKCE pair, then open `/authorize` with its challenge:

   ```
   http://localhost:8787/authorize
     ?client_id=demo-spa
     &redirect_uri=http://localhost:8787/callback
     &response_type=code
     &scope=openid%20profile%20email%20offline_access
     &state=<state>
     &code_challenge=<S256 of your verifier>
     &code_challenge_method=S256
   ```

2. Sign in, then Allow.
3. The browser lands on `/callback?code=...`, which this server does not handle: copy the `code` out of
   the address bar.
4. Exchange it:

   ```bash
   curl -s http://localhost:8787/token \
     -d grant_type=authorization_code \
     -d client_id=demo-spa \
     -d redirect_uri=http://localhost:8787/callback \
     -d code=<code> \
     -d code_verifier=<verifier>
   ```

5. Call `/userinfo` with the `access_token` as a bearer token, and revoke the refresh token with
   `curl -s http://localhost:8787/revoke -d client_id=demo-spa -d token=<refresh_token>`.

Add `prompt=login`, or `max_age=0`, to the authorize URL to be asked to sign in again with a live session.

The `id_token` is signed HS256 with a demo secret from `server.ts`. It is a fixture, not a key to reuse.
