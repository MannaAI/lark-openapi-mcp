# syntax=docker/dockerfile:1

# Builds this repo from source. The upstream image installed the published
# @larksuiteoapi/lark-mcp off npm instead, which in a fork silently ships
# upstream and none of the local changes.
#
# Upstream also ran gnome-keyring + dbus in the container so keytar could hold
# the token-store encryption key. That is gone: its entrypoint rewrote the
# keyring on every boot, so the key changed each start and the storage.json from
# the previous boot could no longer be decrypted -- every restart logged every
# user out, volume or not. Set LARK_MCP_ENCRYPTION_KEY instead (32 bytes hex,
# `openssl rand -hex 32`) and the store actually survives a redeploy.

FROM node:20-bookworm-slim AS build

WORKDIR /app

COPY package.json yarn.lock ./
# --ignore-scripts skips `prepare` (which would run the build before the sources
# are copied) and keytar's native prebuild, which wants libsecret we do not ship.
RUN yarn install --frozen-lockfile --ignore-scripts

COPY tsconfig.json ./
COPY src ./src
RUN yarn build


FROM node:20-bookworm-slim AS runtime

# env-paths resolves the token store to $XDG_DATA_HOME/lark-mcp-nodejs. Pinning
# XDG_DATA_HOME makes the volume mount path explicit -- note the `-nodejs`
# suffix, which the upstream image's documented mount path omitted.
# TRUST_PROXY: this image is meant to run behind a TLS terminator, where the
# client IP only exists in X-Forwarded-For. Off by default in the code so a
# proxy-less `npx` run cannot be IP-spoofed.
ENV NODE_ENV=production \
    XDG_DATA_HOME=/data \
    TRUST_PROXY=1

WORKDIR /app

# As PID 1 a process gets no default signal dispositions, so plain `node` ignores
# SIGTERM and every redeploy waits out the grace period and SIGKILLs mid-write.
# tini forwards it, and node then exits on the default disposition.
# tini: as PID 1 a process gets no default signal dispositions, so plain `node`
# ignores SIGTERM and every redeploy waits out the grace period and SIGKILLs
# mid-write. tini forwards it, and node then exits on the default disposition.
# gosu: the entrypoint has to start as root to chown the mounted volume, then
# drop to `node` -- see docker-entrypoint.sh.
RUN apt-get update \
  && apt-get install -y --no-install-recommends tini gosu \
  && rm -rf /var/lib/apt/lists/*

COPY package.json yarn.lock ./
RUN yarn install --frozen-lockfile --production --ignore-scripts \
  && yarn cache clean

COPY --from=build /app/dist ./dist

COPY docker-entrypoint.sh /usr/local/bin/docker-entrypoint.sh
RUN chmod +x /usr/local/bin/docker-entrypoint.sh

# Deliberately no `USER node`: the entrypoint needs root to chown the volume that
# gets mounted over /data, and drops to `node` itself before exec'ing the server.
EXPOSE 3000

# Everything else the server needs is already env-driven: APP_ID, APP_SECRET,
# LARK_TOOLS, LARK_DOMAIN, LARK_TOKEN_MODE, plus PUBLIC_BASE_URL and
# LARK_MCP_ENCRYPTION_KEY. Run one-off CLI commands by overriding the whole
# command, e.g. `docker run --rm image node dist/cli.js whoami`.
ENTRYPOINT ["/usr/bin/tini", "--", "/usr/local/bin/docker-entrypoint.sh"]

# Shell form so $PORT interpolates; `exec` so node replaces the shell rather than
# sitting under it as a child tini cannot signal.
CMD exec node dist/cli.js mcp --mode streamable --host 0.0.0.0 --port ${PORT:-3000} --oauth
