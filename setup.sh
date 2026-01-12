#!/bin/bash

echo "Starting Network Lab setup..."

# 1. Create data directories if they don't exist
echo "Creating persistence directories..."
mkdir -p authelia/config
mkdir -p postgres_data
mkdir -p estudiantes
sudo chmod -R 777 estudiantes

# 2. Generate .env file from example if it doesn't exist
if [ ! -f .env ]; then
    echo "Creating .env file from example..."
    cp .env.example .env
    
    # 3. Generate random secrets for Authelia
    echo "Generating random secrets for Authelia..."
    JWT_SEC=$(openssl rand -hex 32)
    SES_SEC=$(openssl rand -hex 32)
    ENC_KEY=$(openssl rand -hex 32)
    
    # Replace empty values in .env (using sed)
    sed -i "s/JWT_SECRET=/JWT_SECRET=$JWT_SEC/g" .env
    sed -i "s/SESSION_SECRET=/SESSION_SECRET=$SES_SEC/g" .env
    sed -i "s/STORAGE_ENCRYPTION_KEY=/STORAGE_ENCRYPTION_KEY=$ENC_KEY/g" .env
    
    echo ".env file configured with new secrets."
else
    echo "The .env file already exists. Secrets have not been overwritten."
fi

# 4. Initialize Guacamole database (only if SQL does not exist)
if [ ! -f authelia/initdb.sql ]; then
    echo "Preparing startup script for Postgres/Guacamole..."
    docker run --rm guacamole/guacamole /opt/guacamole/bin/initdb.sh --postgres > ./authelia/initdb.sql
fi

echo "Configuration completed!"
echo "Edit the .env file to adjust your DOMAIN and DB_PASSWORD."
echo "Then run: docker compose up -d --build"