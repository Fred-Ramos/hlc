#!/bin/bash

# Absolute path to the .env file
ENV_PATH="../../../../.env"

# Load .env variables
if [ ! -f "$ENV_PATH" ]; then
    echo "Error: .env file not found at $ENV_PATH"
    exit 1
fi

set -a
source "$ENV_PATH"
set +a

# Ensure required variables are set
if [ -z "$NETWORK_INTERFACE" ]; then
    echo "Error: NETWORK_INTERFACE is not set in the .env file."
    exit 1
fi

# Create capture directory if not exists
HLC_DIR="$PROJECT_PATH/charger_ocpp/evse/hlc"
CAPTURE_DIR="$HLC_DIR/captures"
mkdir -p "$CAPTURE_DIR"
sudo chmod 775 "$CAPTURE_DIR"

# File rotation size in KB (100MB)
FILESIZE_LIMIT_KB=102400

# Use date-based filename prefix
FILE_PREFIX="$CAPTURE_DIR/capture_$(date +%Y-%m-%d_%H-%M-%S)"

# Start tcpdump with file size-based rotation
tcpdump -i "$NETWORK_INTERFACE" -s 0 -C "$FILESIZE_LIMIT_KB" -W 1 -w "${FILE_PREFIX}.pcap"
