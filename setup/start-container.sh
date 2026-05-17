#!/bin/bash
IMAGE_NAME="netem_challenge"
BASE_PORT=8000

# Build the image first
docker build -t $IMAGE_NAME .

NR_OF_CONTAINERS=1
echo "Starting container ..."

CONTAINER_NAME="netem_container"
HOST_PORT=$((BASE_PORT + i))

# Path to the repo root (one level up from setup/)
REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"

docker run -d \
    --name "$CONTAINER_NAME" \
    -p "$HOST_PORT:7681" \
    -v "$REPO_ROOT:/workspace" \
    --memory="2g" \
    --memory-swap="2g" \
    --cpus="4" \
    --pids-limit 50 \
    --restart unless-stopped \
    "$IMAGE_NAME"

echo "Started $CONTAINER_NAME on port $HOST_PORT"
echo "Repo mounted at /workspace inside the container"