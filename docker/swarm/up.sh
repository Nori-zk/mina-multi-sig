#!/bin/bash

# Get the directory where the script is located
SCRIPT_DIR="$(dirname "${BASH_SOURCE[0]}")"

# Change to the script's directory
cd "$SCRIPT_DIR"

# Deploy dev stack
docker stack deploy -c ../docker-compose.server.swarm.yml frost