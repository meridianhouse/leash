#!/usr/bin/env bash
set -euo pipefail

echo "Deploying Leash landing page to meridianhouse.tech/leash..."

REMOTE_HOST="packetflood.org"
REMOTE_USER="ryan"
REMOTE_PATH="/var/www/meridianhousebooks.com/leash"

ssh "${REMOTE_USER}@${REMOTE_HOST}" "mkdir -p ${REMOTE_PATH}"
scp site/index.html "${REMOTE_USER}@${REMOTE_HOST}:${REMOTE_PATH}/"
scp scripts/install.sh "${REMOTE_USER}@${REMOTE_HOST}:${REMOTE_PATH}/"

echo "✅ Deployed to https://meridianhouse.tech/leash"
