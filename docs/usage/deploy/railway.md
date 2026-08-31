# Deploying to Railway

This fork runs as a remote MCP server that an MCP client connects to, where each
user acts with their own Lark identity. The bearer token a client holds *is*
that user's Lark `user_access_token`, so every call runs against what that
employee can already see.

Current state, as of 2026-08-30:

- **Claude connects over OAuth and works.**
- **ChatGPT cannot complete an OAuth flow** — not against this server and not
  against Linear's either, so it is not something to fix here. It connects with
  Authentication set to No Auth and a per-person URL from `/my-token`. See
  [5. ChatGPT](#5-chatgpt).
- **Messages and DMs are not exposed.** `LARK_TOOLS` and `LARK_OAUTH_SCOPES`
  cover docs, drive, wiki and calendar only.

Two things upstream did not support are what make this possible:

- `PUBLIC_BASE_URL` — upstream derived the OAuth callback, the issuer, and the
  discovery metadata from the local bind address, so remote OAuth only worked on
  localhost.
- `LARK_MCP_ENCRYPTION_KEY` — upstream took the token store's encryption key from
  the OS keyring via keytar. See [Why not keytar](#why-not-keytar).

## 1. Lark app

In the Lark developer console:

- Note the **App ID** and **App Secret**.
- Add the permissions the enabled tools need.
- Set the OAuth 2.0 redirect URL to `https://<your-domain>/callback`.

## 2. Railway service

Point a service at this repo. Railway picks up `railway.toml`, which selects the
root `Dockerfile`.

**Volume:** mount one at `/data`. `XDG_DATA_HOME` is pinned to `/data` in the
Dockerfile, so the token store lands at `/data/lark-mcp-nodejs/storage.json`.
Without the volume, every redeploy makes every user reconnect.

The volume mounts over the image's own `/data` and arrives owned by root, so
`docker-entrypoint.sh` chowns it at runtime and then drops to the `node` user.
Skipping that produces `EACCES: permission denied, mkdir '/data/lark-mcp-nodejs'`
at boot, after which `StorageManager` disables the on-disk store and falls back
to memory -- tokens then survive until the next restart and no further.

**Domain:** generate one, or attach a custom domain. Railway terminates TLS.

**Variables:**

| Variable | Value | Notes |
| --- | --- | --- |
| `APP_ID` | `cli_xxxx` | |
| `APP_SECRET` | | |
| `PUBLIC_BASE_URL` | `https://<your-domain>` | No trailing slash needed; one is stripped. Must match the Lark redirect URL's origin. |
| `LARK_MCP_ENCRYPTION_KEY` | `openssl rand -hex 32` | 64 hex characters. Changing it invalidates every stored token. |
| `LARK_DOMAIN` | `https://open.larksuite.com` | Only for Lark international; defaults to `https://open.feishu.cn` for Feishu. |
| `LARK_TOKEN_MODE` | `user_access_token` | |
| `LARK_TOOLS` | see below | Comma-separated. Deliberately excludes every `im.*` tool. |
| `TRUST_PROXY` | `1` | Already set in the image. Without it the SDK's auth router rate-limits every user under the proxy's single IP. |
| `LARK_OAUTH_SCOPES` | see below | Space-separated. Must be non-empty, or the server falls back to the legacy `authen/v1` flow. |

`LARK_TOOLS` as deployed -- docs, drive, wiki and calendar, read and write:

```
docx.builtin.search,docx.builtin.import,docx.v1.document.get,
docx.v1.document.rawContent,docx.v1.document.create,docx.v1.documentBlock.list,
docx.v1.documentBlock.patch,docx.v1.documentBlock.batchUpdate,
docx.v1.documentBlockChildren.create,docx.v1.documentBlockChildren.batchDelete,
docx.v1.documentBlockDescendant.create,drive.v1.file.list,
drive.v1.file.createFolder,drive.v1.meta.batchQuery,wiki.v2.space.list,
wiki.v2.space.getNode,wiki.v2.spaceNode.list,calendar.v4.calendar.list,
calendar.v4.calendar.primary,calendar.v4.calendarEvent.list,
calendar.v4.calendarEvent.get,calendar.v4.calendarEvent.search,
calendar.v4.calendarEvent.instances,calendar.v4.calendarEvent.create,
calendar.v4.calendarEvent.patch,calendar.v4.calendarEvent.delete,
calendar.v4.calendarEventAttendee.list,calendar.v4.calendarEventAttendee.create,
calendar.v4.freebusy.list,contact.v3.user.get,contact.v3.user.batch
```

`LARK_OAUTH_SCOPES` to match:

```
docx:document drive:drive wiki:wiki
calendar:calendar calendar:calendar:readonly
calendar:calendar.event:read calendar:calendar.event:create
calendar:calendar.event:update calendar:calendar.event:delete
calendar:calendar.free_busy:read
contact:contact.base:readonly contact:user.base:readonly
contact:user.employee_id:readonly
```

`calendar:calendar:readonly` is not redundant with `calendar:calendar`, however
much the names suggest it. Lark is moving calendar off the coarse scope one
endpoint at a time, and `calendar/v4/calendars/primary` has already gone: it
accepts `calendar:calendar:read` or `calendar:calendar:readonly` and nothing
else, while `calendars/list` and `calendar_events/list` next to it still take
`calendar:calendar`. So the neighbours work and one call answers `99991679`,
which reads as a broken token rather than a missing permission. Check the
per-endpoint list in the reference before assuming a family shares a scope.

The `contact:*` entries are there because `LARK_TOOLS` enables
`contact.v3.user.get` and `contact.v3.user.batch`, which had no scope at all --
and because calendar responses carry a `user_id` that Lark treats as sensitive
and gates behind `contact:user.employee_id:readonly` separately from the calendar
scopes themselves.

The same permissions have to be granted to the Lark app itself and the version
published, or the calendar tools fail no matter what is advertised here. Scope
names came from `larksuite/cli`'s own registry
(`internal/registry/scope_priorities.json`), not from the published reference,
which contradicts the product often enough to be worth distrusting.

`offline_access` is not in that list because the server adds it itself
(`advertisedScopes()`), but it still has to be **enabled on the app** under
Permission Management, and it is the one scope whose absence does not look like a
scope problem. Lark returns a `refresh_token` only when `offline_access` was
granted, and only includes one in a refresh response when the request's `scope`
carries it. Without it every user token simply stops working two hours after
sign-in, and the client reports "user authorization is expired/invalid" -- there
is no permission error anywhere. The check is one deploy-log line:

```
Successfully exchanged authorization code for client my-token; ... refreshToken: true
```

`false` there means the app does not have the permission, whatever the code asked
for. Lark also makes `refresh_token` single-use and invalidates the previous one
immediately, which is why `LarkAuthHandler.refreshToken` allows only one refresh
in flight per token -- parallel tool calls otherwise race to spend the same one
and the loser reports a dead session moments after a refresh that worked.

**Do not set `USER_ACCESS_TOKEN`.** The transport only starts the OAuth flow when
no static token is configured (`src/mcp-server/transport/streamable.ts`), so
setting it silently turns every user into one shared service account.

`PORT`, `--host 0.0.0.0`, `--mode streamable`, and `--oauth` are handled by the
Dockerfile's `CMD`.

**Check the boot logs once.** `[StorageManager]` should be silent. A line about
the store being disabled means tokens are memory-only, which looks completely
healthy from outside -- OAuth works, tools work -- right up until the next
restart logs everyone out.

## 3. GitHub Actions

`.github/workflows/deploy.yml` deploys on push to `main`. It needs a `production`
GitHub environment holding:

- `RAILWAY_API_TOKEN`
- `RAILWAY_PROJECT_ID`
- `RAILWAY_ENVIRONMENT_ID`
- `RAILWAY_SERVICE_ID`

## 4. Connect the client

Point the MCP client at `https://<your-domain>/mcp`. Discovery is served from
`PUBLIC_BASE_URL`:

- `/.well-known/oauth-protected-resource/mcp`
- `/.well-known/oauth-protected-resource` (same document, for clients that
  predate the path-inserted form in RFC 9728 s3.1)
- `/.well-known/oauth-authorization-server`

A 401 also carries `WWW-Authenticate: Bearer ..., resource_metadata="..."` for
clients that discover auth from the challenge rather than by probing.

`token_endpoint_auth_methods_supported` lists the methods the token endpoint can
actually verify -- `client_secret_post`, `none`, and `private_key_jwt` for a
client whose `client_id` is a metadata document -- and `/register` will not hand
back anything else: a client
that omits `token_endpoint_auth_method`, or asks for one of the methods that
reads credentials from the `Authorization` header, is registered as a public
client instead. Otherwise it leaves holding a `client_secret` that nothing here
accepts -- and a client that compares its registration against the metadata
before authorizing, as ChatGPT does, abandons the flow the moment it registers,
without ever opening the authorize URL, so no login prompt appears at all.

`/register` logs the requested auth method, redirect URIs, grant types and
scope, which is the only visibility there is into a client that gives up
silently.

**Scopes.** With `LARK_OAUTH_SCOPES` unset nothing is advertised, and a client
that offers to request scopes has an empty list to choose from -- ChatGPT says
so in as many words. Setting it advertises the list and also becomes the default
scope recorded for a client that registers without one, which matters because
`/authorize` rejects any scope the client was not registered with and bounces
the error to the client's own redirect URI, where it is invisible from here.

Advertised scopes are discovery metadata, not enforcement: the OIDC provider
does not forward them to Lark, which grants whatever the app itself was granted.
Narrow what a token can reach through the Lark console and `LARK_TOOLS`, not
here.

Verify before wiring up a client:

```bash
curl -s https://<your-domain>/.well-known/oauth-protected-resource/mcp
# {"resource":"https://<your-domain>/mcp",
#  "authorization_servers":["https://<your-domain>"]}
# Both must be the public HTTPS origin, never http://localhost:3000.
# `resource` is the MCP endpoint, and has to match the `resource` parameter the
# client sends. No trailing slash on the issuer: RFC 8414 s3.3 requires it to be
# identical to the identifier the well-known path was inserted into, and the SDK
# publishes URL.href, which appends one. See `oauthMetadata` in
# src/auth/handler/handler.ts.

curl -si -X POST https://<your-domain>/mcp \
  -H 'Content-Type: application/json' \
  -d '{"jsonrpc":"2.0","id":1,"method":"initialize"}' | grep -i '^www-authenticate'
# WWW-Authenticate: Bearer error="invalid_token", ...
#   resource_metadata="https://<your-domain>/.well-known/oauth-protected-resource/mcp"
```

The same checks run locally against the image:

```bash
docker build -t lark-mcp .
docker run --rm -p 3000:3000 \
  -e APP_ID=cli_dummy -e APP_SECRET=dummy \
  -e PUBLIC_BASE_URL=https://lark-mcp.example.com \
  -e LARK_MCP_ENCRYPTION_KEY=$(openssl rand -hex 32) \
  lark-mcp
```

## 5. ChatGPT

**ChatGPT cannot complete an OAuth flow against a custom connector.** It runs
discovery, registers a client at `/register`, gets its 201, and then never opens
an authorization window: `/authorize` is never requested, and no Connect or Sign
in control appears anywhere in its UI. The connector reports "no actions found".

This is not a fault in this server, and the cheap experiment that proves it is
worth repeating before anyone spends time here again: add
`https://mcp.linear.app/mcp` -- Linear's own server, an official ChatGPT
connector -- as a *custom* connector with OAuth. It fails identically. Same
symptom is open at
[twentyhq/twenty#20296](https://github.com/twentyhq/twenty/issues/20296),
reproduced there against Claude Code CLI too.

Everything else about ChatGPT does work, after four fixes that are easy to
regress. They live in `src/mcp-server/transport/streamable.ts`:

- It posts JSON-RPC as `Content-Type: application/octet-stream`, which
  `express.json()` declines to parse, so every request arrived with an empty
  body and read as anonymous.
- The SDK's transport then rejects that content type itself with 415, and
  answers 406 unless `Accept` lists both `application/json` and
  `text/event-stream`.
- Rewriting `req.headers` does nothing: the SDK hands the raw Node request to
  Hono, which builds its `Headers` from `rawHeaders`. Both have to be written.
- **Never answer ChatGPT with HTTP 401.** Its opening probe is an empty POST and
  it enumerates actions with `server/discover`, which is not in the MCP spec. A
  401 to either is read as a verdict on the whole connector, surfaced as
  `upstream_status: 401`, and it stops. `mcp.deepwiki.com`, which ChatGPT
  connects to happily, answers those two with 400 and with 200-plus-JSON-RPC-error.
  Refuse at the JSON-RPC layer, not the HTTP one.

That last one is why auth is gated on a *denylist* of methods that carry
identity (`tools/call`, `resources/read`, `prompts/get`, `completion/complete`)
rather than an allowlist of safe ones. An allowlist fails closed against every
method nobody thought of, and clients keep inventing them.

### Connecting ChatGPT without OAuth

Until OpenAI fixes the above, a person carries their own token:

1. Open `https://<your-domain>/my-token` and sign in to Lark.
2. Copy the URL the page gives back -- `https://<your-domain>/mcp/u/h_...`.
3. In ChatGPT, create an app with that URL and set **Authentication: No Auth**.

ChatGPT offers "Access token / API key" with Bearer and Custom Header schemes,
but only ever collects the header *name*; the value is meant to arrive at the
same later step that OAuth's Connect button is missing from. So the credential
has to travel in the path. Make's MCP server ships the same shape for the same
reason. A path segment is accepted where a query parameter gets flagged unsafe.

The path segment is a **handle**, not the Lark token. A Lark `access_token`
lasts about two hours; the refresh flow replaces it and deletes the old one, so
a URL built around the token itself dies at the first refresh. A handle names
whichever token currently belongs to it, `refreshToken` moves it onto the
replacement before dropping the old, and `clearExpiredTokens` prunes handles
whose token has gone. A leaked connector URL is also worth less than a leaked
token: it means nothing anywhere but this server.

**Every person needs their own app.** The handle is the identity, so a shared
app means a shared identity, and everyone's queries run as whoever set it up.
That is what OAuth would have fixed. Do not publish the app to the workspace.

`/mcp` is unchanged and still prefers the `Authorization` header, so Claude and
anything else that can complete OAuth is unaffected.

## Reading messages

**The deployed configuration no longer exposes messages at all.** `LARK_TOOLS`
and `LARK_OAUTH_SCOPES` were narrowed to docs, drive, wiki and calendar, because
a ChatGPT connector cannot yet be shared without sharing one person's identity
with it, and DMs are the wrong thing to have in that blast radius. The rest of
this section is kept because it is what made messages work, and re-enabling them
is a matter of putting the `im.*` tools and `im:*` scopes back.

`LARK_OAUTH_SCOPES` is not cosmetic. Leaving it unset makes `LarkAuthHandler`
select `LarkOIDC2OAuthServerProvider`, the legacy `authen/v1` flow, and the newer
IM endpoints reject the tokens it mints:

    99991695 The current user authorization API is a legacy version and does not
             support this capability.

Setting it selects `LarkOAuth2OAuthServerProvider` and its `authen/v2` flow,
which is what makes reading messages possible at all. Anyone who authorized
before it was set must reconnect -- their existing token was minted by the old
flow and cannot be upgraded.

Direct messages need `im:message.p2p_msg:get_as_user` on top of
`im:message:readonly`; without it Lark answers `230027` and names the scope.

`im.v1.chat.list`, `.search` and `.get` additionally require the **Bot**
capability on the Lark app -- they answer `232025 Bot ability is not activated`
without it, even on a user token. `im.builtin.messageSearch` and
`im.v1.chatMembers.get` do not, so message search works without ever enabling a
bot.

## Read-only vs write tools

Tools are registered with MCP's `readOnlyHint` annotation, inferred from `GET`
plus a named list of read-only `POST` endpoints in
`src/mcp-tool/utils/is-read-only.ts`. A client that sees no hint treats a tool as
a write, which in ChatGPT means a per-call confirmation and, on some workspace
plans, being blocked outright -- so an unannotated read-only server can appear to
have no usable actions at all.

The list is opt-in for a reason: labelling a write as read-only lets a client
call it without asking. Anything not `GET` and not named there stays a write.

## Constraints

**Single replica.** `railway.toml` pins `numReplicas = 1`. `AuthStore` keeps
tokens, and the handle map behind every `/mcp/u/...` URL, in one encrypted file
plus an in-process cache. A user who authorizes against one replica gets a 401
from any other, and a connector URL issued by one resolves to nothing on the
rest. Scaling out means giving `AuthStore` a shared backend (Redis or Postgres)
first.

**Shared permission ceiling is per-user, not per-app.** Each user's token is
their own, so the server never sees more than that employee can. But anything an
employee can read, ChatGPT can read on their behalf — scope `LARK_TOOLS` to the
read-only set you actually want exposed.

## Why not keytar

Upstream's image installed `libsecret`, `gnome-keyring`, and `dbus`, and ran a
~70-line entrypoint to stand up a keyring so keytar could store the AES key.

It could not have worked in a container. The entrypoint rewrote
`login.keyring` on every boot, so keytar found no existing password and
`StorageManager` generated a fresh key. The `storage.json` written by the
previous boot was encrypted under the old key, so `loadStorageData` threw,
caught its own error, and returned an empty store — every restart logged every
user out, and the only trace was a warning. The documented volume path was also
missing `env-paths`' `-nodejs` suffix, so it mounted over nothing.

`LARK_MCP_ENCRYPTION_KEY` replaces all of it. keytar remains the default for
local CLI use, where an OS keyring genuinely exists.
