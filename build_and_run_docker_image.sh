#!/bin/bash

# Define network name
NETWORK_NAME=my_network

# Create a user-defined bridge network if it doesn't exist
if [ ! "$(docker network ls --format '{{.Name}}' | grep -w $NETWORK_NAME)" ]; then
  echo "Creating a network: $NETWORK_NAME..."
  docker network create $NETWORK_NAME
else
  echo "Network $NETWORK_NAME already exists."
fi

# Check if the Redis container is running
if docker ps -a --format '{{.Names}}' | grep -q '^redis_container$'; then
  echo "Stopping and removing existing redis_container..."
  docker stop redis_container
  docker rm redis_container
fi

# Run the Redis container in detached mode
echo "Starting a new Redis container..."
docker run -p 6379:6379 --network $NETWORK_NAME --name redis_container -d redis:latest

# Wait for Redis container to fully start (adjust sleep time as needed)
sleep 5

# Check if the MongoDB container is running
if docker ps -a --format '{{.Names}}' | grep -q '^mongodb_container$'; then
  echo "Stopping and removing existing mongodb_container..."
  docker stop mongodb_container
  docker rm mongodb_container
fi

# Run the MongoDB container and connect it to the custom bridge network
echo "Starting a new MongoDB container..."
docker run -d --network $NETWORK_NAME --name mongodb_container -p 27017:27017 mongo:6.0.9

# Wait for MongoDB container to fully start (adjust sleep time as needed)
sleep 5

# Build the FastAPI application image
echo "Building the FastAPI application image..."
docker build --no-cache -t fastapi-app .

# Run the FastAPI application container
echo "Starting the FastAPI application..."
docker run --rm -it --network $NETWORK_NAME \
  -e REDIS_HOST=redis_container \
  -e MONGO_DETAILS=mongodb://mongodb_container:27017 \
  -p 8000:8000/tcp fastapi-app:latest