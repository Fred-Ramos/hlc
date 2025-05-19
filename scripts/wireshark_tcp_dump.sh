#!/bin/bash

# Define path to .env file
ENV_PATH="../../../../.env"

# Check if .env file exists
if [ ! -f "$ENV_PATH" ]; then
    echo "Error: .env file not found at $ENV_PATH. The script will now exit."
    exit 1
fi

# Export all variables loaded from .env
set -a
source "$ENV_PATH"
set +a

# Make sure required variables are set
if [ -z "$NETWORK_INTERFACE" ] || [ -z "$ISO_OPERATOR_IP" ]; then
    echo "Error: NETWORK_INTERFACE or ISO_OPERATOR_IP is not set in the .env file."
    exit 1
fi

# Start tcpdump and stream it to the operator via netcat
sudo tcpdump -i "$NETWORK_INTERFACE" -s 0 -U -w - | nc "$ISO_OPERATOR_IP" 15200
