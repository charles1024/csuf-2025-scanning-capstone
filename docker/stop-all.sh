#!/bin/bash

set -e

# Recursively find all docker-compose.yml files and stop their stacks
while IFS= read -r -d '' compose_file; do
    dir=$(dirname "$compose_file")
    echo "=== Entering $dir ==="
    cd "$dir"

    echo "Stopping containers: docker compose down"
    docker compose down || echo "Failed to stop containers in $dir"

    echo ""
    cd - >/dev/null

done < <(find . -type f \( -name "docker-compose.yml" -o -name "docker-compose.yaml" \) -print0)

echo "All Docker environments stopped."
