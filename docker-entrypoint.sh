#!/bin/sh
set -e

# A platform volume (Railway, Fly, plain `docker run -v`) mounts over whatever the
# image put at this path, and it arrives owned by root. Any chown done at build
# time is underneath the mount and therefore invisible, so an unprivileged user
# cannot create the token store directory:
#
#   EACCES: permission denied, mkdir '/data/lark-mcp-nodejs'
#
# StorageManager catches that, disables the on-disk store, and falls back to
# memory -- so tokens silently vanish on every restart. Fixing ownership has to
# happen at runtime, after the mount exists, which means starting as root and
# dropping privileges here rather than via a build-time USER.
if [ "$(id -u)" = '0' ]; then
  mkdir -p "${XDG_DATA_HOME:-/data}"
  chown -R node:node "${XDG_DATA_HOME:-/data}"
  exec gosu node "$@"
fi

exec "$@"
