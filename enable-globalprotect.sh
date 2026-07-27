#!/bin/bash
# Enable GlobalProtect auto-start and start it immediately

SERVICE="gpd.service"

echo "Enabling $SERVICE..."
sudo systemctl enable "$SERVICE"

echo "Starting $SERVICE..."
sudo systemctl start "$SERVICE"

echo "Done. Current status:"
systemctl is-enabled "$SERVICE"
systemctl is-active "$SERVICE"
