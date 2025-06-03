#!/bin/bash

# Load PROJECT_PATH from .env
ENV_PATH="../../../../.env"

if [ ! -f "$ENV_PATH" ]; then
    echo "ERROR: .env file not found at $ENV_PATH"
    exit 1
fi

# Export env vars
set -a
source "$ENV_PATH"
set +a

# Validate required variable
if [ -z "$PROJECT_PATH" ]; then
    echo "ERROR: PROJECT_PATH is not set in .env"
    exit 1
fi

# Set paths
SCRIPT_DIR="$PROJECT_PATH/charger_ocpp/evse/hlc/scripts"
SCRIPT_PATH="$SCRIPT_DIR/capture_script.sh"
SERVICE_NAME="packet-capture.service"
SERVICE_PATH="/etc/systemd/system/$SERVICE_NAME"
ENV_ABS_PATH="$PROJECT_PATH/.env"

# Ensure script is executable
chmod +x "$SCRIPT_PATH"

# Create systemd service file
echo "Creating systemd service at $SERVICE_PATH..."

sudo tee "$SERVICE_PATH" > /dev/null <<EOF
[Unit]
Description=Packet Capture Service with Rotation
After=network.target

[Service]
User=pi
Type=simple
WorkingDirectory=$SCRIPT_DIR
EnvironmentFile=$ENV_ABS_PATH
ExecStart=$SCRIPT_PATH
Restart=always
RestartSec=5s
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
EOF

# Reload and launch service
echo "Reloading systemd..."
sudo systemctl daemon-reload

echo "Enabling $SERVICE_NAME..."
sudo systemctl enable "$SERVICE_NAME"

echo "Starting $SERVICE_NAME..."
sudo systemctl restart "$SERVICE_NAME"

echo "Service status:"
sudo systemctl status "$SERVICE_NAME" --no-pager
