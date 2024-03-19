#!/usr/bin/bash

# Define the container name
container_name="my-postgres-container"

# Check if the PostgreSQL container is already running
if sudo docker ps -a --format '{{.Names}}' | grep -q "^$container_name$"; then
    echo "Shutting down docker and Postgres"
    echo -n "[STOPPED] "
    sudo docker stop $container_name
    echo -n "[REMOVED] "
    sudo docker rm $container_name
fi

echo "[DONE]"
