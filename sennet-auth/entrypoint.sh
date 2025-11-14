#!/bin/bash

# Use the DEPLOY_MODE value as conditions
DEPLOY_MODE=${DEPLOY_MODE}

# Pass the HOST_UID and HOST_UID from environment variables specified in the child image docker-compose
HOST_GID=${HOST_GID}
HOST_UID=${HOST_UID}

echo "Starting sennet-auth container with the same host user UID: $HOST_UID and GID: $HOST_GID"

# No SSL in localhost mode
if [ $DEPLOY_MODE != "localhost"  ]; then
    chown -R codcc:codcc /etc/letsencrypt
fi

# Start nginx in background
# 'daemon off;' is nginx configuration directive
nginx -g 'daemon off;' &

# Start uwsgi and keep it running in foreground
uwsgi --ini /usr/src/app/src/uwsgi.ini
