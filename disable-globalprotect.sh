#!/bin/bash
# Disable GlobalProtect auto-start and stop it if running

SERVICE="gpd.service"

echo "Disabling $SERVICE..."
sudo systemctl disable "$SERVICE"

echo "Stopping $SERVICE..."
sudo systemctl stop "$SERVICE"

echo "Done. Current status:"
systemctl is-enabled "$SERVICE"
systemctl is-active "$SERVICE"
