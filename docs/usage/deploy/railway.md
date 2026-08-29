# Deploying to Railway

This fork runs as a remote MCP server that ChatGPT (or any MCP client supporting
OAuth) connects to, where each user authorizes with their own Lark identity. The
bearer token an MCP client holds *is* that user's Lark `user_access_token`, so
searches run against what that employee can see, including their own DMs.

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
| `LARK_TOOLS` | `search.v2.message.create,docx.builtin.search,docx.v1.document.rawContent` | Read-only search + document retrieval. |

**Do not set `USER_ACCESS_TOKEN`.** The transport only starts the OAuth flow when
no static token is configured (`src/mcp-server/transport/streamable.ts`), so
setting it silently turns every user into one shared service account.

`PORT`, `--host 0.0.0.0`, `--mode streamable`, and `--oauth` are handled by the
Dockerfile's `CMD`.

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

- `/.well-known/oauth-protected-resource`
- `/.well-known/oauth-authorization-server`

A 401 also carries `WWW-Authenticate: Bearer ..., resource_metadata="..."` for
clients that discover auth from the challenge rather than by probing.

Verify before wiring up a client:

```bash
curl -s https://<your-domain>/.well-known/oauth-protected-resource
# {"resource":"https://<your-domain>/",
#  "authorization_servers":["https://<your-domain>/"]}
# Both must be the public HTTPS origin, never http://localhost:3000.
# The trailing slash is URL normalisation and is expected either way.

curl -si -X POST https://<your-domain>/mcp \
  -H 'Content-Type: application/json' \
  -d '{"jsonrpc":"2.0","id":1,"method":"initialize"}' | grep -i '^www-authenticate'
# WWW-Authenticate: Bearer error="invalid_token", ...
#   resource_metadata="https://<your-domain>/.well-known/oauth-protected-resource"
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

## Constraints

**Single replica.** `railway.toml` pins `numReplicas = 1`. `AuthStore` keeps
tokens in one encrypted file plus an in-process cache, so a user who authorizes
against one replica gets a 401 from any other. Scaling out means giving
`AuthStore` a shared backend (Redis or Postgres) first.

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
