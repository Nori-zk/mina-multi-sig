#!/bin/bash

# Create the web network with encryption, attachable, and Swarm scope
docker network create \
  --driver overlay \
  --opt encrypted \
  --attachable \
  --scope swarm \
  web

# Create the caddy_controller network with a specified subnet and gateway
docker network create \
  --driver overlay \
  --opt encrypted \
  --attachable \
  --scope swarm \
  --subnet 10.200.200.0/24 \
  --gateway 10.200.200.1 \
  caddy_controller

echo "Created networks:"
docker network ls
