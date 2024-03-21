#!/usr/bin/bash

# Start docker
sudo systemctl start docker

# Define the container name
container_name="my-postgres-container"

# Check if the PostgreSQL container is already running
if sudo docker ps -a --format '{{.Names}}' | grep -q "^$container_name$"; then
    echo "PostgreSQL container is already running!"
    echo -n "[STOPPED] "
    sudo docker stop $container_name
    echo -n "[REMOVED] "
    sudo docker rm $container_name
fi

# Start the PostgreSQL container
echo "Starting PostgreSQL container..."
sudo docker run -d \
    --name $container_name  \
    -v $(pwd)/data:/var/lib/postgresql/data \
    -e POSTGRES_PASSWORD=mysecretpassword \
    -p 5432:5432 \
    postgres:latest

# Run the Go application
echo "Starting Go application..."
sleep 2 # Add delay before starting the go server
go run ./cmd/belote/main.go
