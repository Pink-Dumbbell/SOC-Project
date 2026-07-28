#!/bin/bash

set -e

cd "$(dirname "$0")/.."

mkdir -p apache/logs
touch apache/logs/.gitkeep

docker compose down
docker compose build
docker compose up -d

echo "[OK] Target Docker services started."
docker ps
echo "Apache access log: $(pwd)/apache/logs/access.log"
