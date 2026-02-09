#!/bin/bash

set -e

# Recursively iterate through all docker-compose.yml files
while IFS= read -r -d '' compose_file; do
    dir=$(dirname "$compose_file")
    echo "=== Entering $dir ==="
    cd "$dir"

    # ---------- Airflow special case ----------
    if [[ "$dir" == */airflow/* ]]; then
        echo "[Airflow] Running init: docker compose run airflow-init"
        docker-compose run airflow-init || echo "airflow-init failed, continuing..."
    fi

    # ---------- Tomcat special case ----------
    if [[ "$dir" == */tomcat/* ]]; then
        echo "[Tomcat] Running build: docker compose build"
        docker-compose build
    fi

    # ---------- Common start ----------
    echo "Starting containers: docker compose up -d"
    docker-compose up -d

    echo ""
    cd - >/dev/null

done < <(find . -type f \( -name "docker-compose.yml" -o -name "docker-compose.yaml" \) -print0)

echo "All Docker environments started."

