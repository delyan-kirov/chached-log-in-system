#!/bin/bash

# Stop and remove existing PostgreSQL container if it exists
existing_postgres_container=$(docker ps -aqf "name=my-postgres-container")
if [ ! -z "$existing_postgres_container" ]; then
    echo "Removing existing PostgreSQL container..."
    docker stop $existing_postgres_container
    docker rm $existing_postgres_container
fi

# Stop and remove existing Redis container if it exists
existing_redis_container=$(docker ps -aqf "name=my-redis-container")
if [ ! -z "$existing_redis_container" ]; then
    echo "Removing existing Redis container..."
    docker stop $existing_redis_container
    docker rm $existing_redis_container
fi

# Start Docker Compose
echo "Starting Docker Compose..."
docker-compose up -d

# Run the Go application
echo "Starting Go application..."
# sleep 1 # Add delay before starting the go server
go run ./cmd/belote/main.go
