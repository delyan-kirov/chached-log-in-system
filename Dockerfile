# Use the official PostgreSQL image from Docker Hub
FROM postgres

# Set environment variables
ENV POSTGRES_PASSWORD=mysecretpassword

# Expose PostgreSQL port
EXPOSE 5432
