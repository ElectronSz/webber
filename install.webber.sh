#!/bin/bash

# Configuration for Webber Production Install
SERVICE_NAME="webber"
BINARY_NAME="webber"
INSTALL_DIR="/usr/local/bin"
CONFIG_DIR="/etc/webber"
STATIC_DIR="/var/www/webber"
USER="webber"
GROUP="webber"
WEBBER_BINARY_URL="https://github.com/ElectronSz/webber/releases/download/v1.0.1/webber"
TMP_DOWNLOAD_DIR="/tmp"

# Ensure script is run as root
if [ "$EUID" -ne 0 ]; then
  echo "Please run as root (sudo)"
  exit 1
fi

# Create user and group for webber
echo "Creating user and group for $SERVICE_NAME..."
if ! id "$USER" >/dev/null 2>&1; then
  useradd -r -s /bin/false "$USER"
fi
if ! getent group "$GROUP" >/dev/null 2>&1; then
  groupadd -r "$GROUP"
fi
usermod -a -G "$GROUP" "$USER" # Ensure user is in the group

# Create directories
echo "Creating necessary directories..."
mkdir -p "$CONFIG_DIR" || { echo "Failed to create config directory"; exit 1; }
mkdir -p "$STATIC_DIR" || { echo "Failed to create static directory"; exit 1; }

# Set ownership and permissions for static directory
chown "$USER:$GROUP" "$STATIC_DIR"
chmod 755 "$STATIC_DIR"

# Download the webber binary
echo "Downloading Webber binary from $WEBBER_BINARY_URL..."
wget -q -O "$TMP_DOWNLOAD_DIR/$BINARY_NAME" "$WEBBER_BINARY_URL"
if [ $? -ne 0 ]; then
  echo "Failed to download Webber binary. Please check the URL or your network connection."
  exit 1
fi

# Move binary to install directory and make it executable
echo "Installing Webber binary to $INSTALL_DIR..."
mv "$TMP_DOWNLOAD_DIR/$BINARY_NAME" "$INSTALL_DIR/$BINARY_NAME" || { echo "Failed to move binary"; exit 1; }
chmod +x "$INSTALL_DIR/$BINARY_NAME"

# Create a default config.json if it doesn't exist
# IMPORTANT: Customize this config.json for your production environment!
echo "Creating default config.json in $CONFIG_DIR..."
if [ ! -f "$CONFIG_DIR/config.json" ]; then
  cat > "$CONFIG_DIR/config.json" <<EOF
{
  "port": "443",
  "static_dir": "./static",
  "proxy_targets": ["http://localhost:8081", "http://localhost:8082"],
  "rate_limit_rps": 10.0,
  "rate_limit_burst": 20,
  "cache_ttl_seconds": 300
}
EOF
  echo "Default config.json created. Please review and customize it for your needs."
else
  echo "config.json already exists in $CONFIG_DIR. Skipping creation."
fi
chown "$USER:$GROUP" "$CONFIG_DIR/config.json"
chmod 644 "$CONFIG_DIR/config.json"

# Create a placeholder static directory within config_dir for symlink if needed
# The webber binary expects 'static' relative to its working directory.
mkdir -p "$CONFIG_DIR/static"
# Create symlink for the actual static directory inside the config directory
# This makes the /var/www/webber content accessible via the 'static' path
# relative to the webber binary's working directory (/etc/webber).
echo "Creating symlink for static content..."
if [ -d "$STATIC_DIR" ]; then
  # Remove any existing symlink or directory named 'static' in CONFIG_DIR
  rm -rf "$CONFIG_DIR/static"
  ln -s "$STATIC_DIR" "$CONFIG_DIR/static" || { echo "Failed to create symlink for static directory"; exit 1; }
fi
chown -R "$USER:$GROUP" "$CONFIG_DIR/static" # Ensure the symlink target has correct permissions
chmod -R 755 "$CONFIG_DIR/static"


# Generate self-signed certificates if not provided
echo "Checking for TLS certificates..."
if [ ! -f "$CONFIG_DIR/cert.pem" ] || [ ! -f "$CONFIG_DIR/key.pem" ]; then
  echo "Generating self-signed TLS certificates. For production, use proper certificates!"
  openssl req -x509 -newkey rsa:4096 -keyout "$CONFIG_DIR/key.pem" -out "$CONFIG_DIR/cert.pem" -days 365 -nodes -subj "/CN=localhost"
  if [ $? -ne 0 ]; then
    echo "Failed to generate certificates."
    exit 1
  fi
else
  echo "Existing certificates found. Skipping generation."
fi
chown "$USER:$GROUP" "$CONFIG_DIR/cert.pem" "$CONFIG_DIR/key.pem"
chmod 600 "$CONFIG_DIR/cert.pem" "$CONFIG_DIR/key.pem"

# Grant CAP_NET_BIND_SERVICE capability to the binary
echo "Granting CAP_NET_BIND_SERVICE capability to $BINARY_NAME..."
setcap 'cap_net_bind_service=+ep' "$INSTALL_DIR/$BINARY_NAME"
if [ $? -ne 0 ]; then
  echo "Failed to set capabilities. This might prevent binding to privileged ports (e.g., 443)."
  # This is not a fatal error for the script, but a warning.
fi

# Create systemd service file with better restart policy
echo "Creating systemd service file for $SERVICE_NAME..."
cat > /etc/systemd/system/"$SERVICE_NAME".service <<EOF
[Unit]
Description=Webber Web Server
After=network.target

[Service]
ExecStart=$INSTALL_DIR/$BINARY_NAME
WorkingDirectory=$CONFIG_DIR
User=$USER
Group=$GROUP
Restart=always
RestartSec=5
# Log stdout/stderr to journalctl
StandardOutput=journal
StandardError=journal
Environment=DEBUG=0 # Set to 0 for production, 1 for debug if supported by webber

[Install]
WantedBy=multi-user.target
EOF

# Enable and start service
echo "Reloading systemd daemon, enabling and starting $SERVICE_NAME service..."
systemctl daemon-reload
systemctl enable "$SERVICE_NAME"
systemctl start "$SERVICE_NAME"

# Check service status
echo "Checking $SERVICE_NAME service status..."
if systemctl is-active "$SERVICE_NAME" >/dev/null; then
  echo "Installation complete. Service $SERVICE_NAME is running."
  echo "Access at https://localhost:443 (or your server's IP/hostname)"
else
  echo "Service failed to start. Check logs with 'journalctl -u $SERVICE_NAME' for details."
  exit 1
fi

echo "Cleanup temporary download file..."
rm -f "$TMP_DOWNLOAD_DIR/$BINARY_NAME"
echo "Webber installation script completed successfully."
