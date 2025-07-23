#!/bin/bash

# Configuration
SERVICE_NAME="webber"
BINARY_NAME="webber"
INSTALL_DIR="/usr/local/bin"
CONFIG_DIR="/etc/webber"
STATIC_DIR="/var/www/webber"
USER="webber"
GROUP="webber"

# Ensure script is run as root
if [ "$EUID" -ne 0 ]; then
  echo "Please run as root (sudo)"
  exit 1
fi

# Create user and group
if ! id "$USER" >/dev/null 2>&1; then
  useradd -r -s /bin/false "$USER"
fi

# Build Go binary
echo "Building Webber web server."
go build -o "$BINARY_NAME" main.go
if [ $? -ne 0 ]; then
  echo "Build failed"
  exit 1
fi

# Create directories
mkdir -p "$CONFIG_DIR" || { echo "Failed to create config directory"; exit 1; }
mkdir -p "$STATIC_DIR" || { echo "Failed to create static directory"; exit 1; }
chown "$USER:$GROUP" "$STATIC_DIR"
chmod 755 "$STATIC_DIR"

# Copy files
cp "$BINARY_NAME" "$INSTALL_DIR/" || { echo "Failed to copy binary"; exit 1; }
cp config.json "$CONFIG_DIR/" || { echo "Failed to copy config"; exit 1; }
if [ -d "static" ]; then
  cp -r static/* "$STATIC_DIR/" || { echo "Failed to copy static files"; exit 1; }
fi
chown "$USER:$GROUP" "$CONFIG_DIR/config.json"
chmod 644 "$CONFIG_DIR/config.json"

# Create symlink for static directory
mkdir -p "$CONFIG_DIR/static" || { echo "Failed to create static config directory"; exit 1; }
if [ "$(ls -A "$STATIC_DIR")" ]; then
  ln -sf "$STATIC_DIR"/* "$CONFIG_DIR/static/" || { echo "Failed to create symlinks"; exit 1; }
fi
chown -R "$USER:$GROUP" "$CONFIG_DIR/static"
chmod -R 755 "$CONFIG_DIR/static"

# Generate self-signed certificates if not provided
if [ ! -f "$CONFIG_DIR/cert.pem" ] || [ ! -f "$CONFIG_DIR/key.pem" ]; then
  echo "Generating self-signed TLS certificates..."
  openssl req -x509 -newkey rsa:4096 -keyout "$CONFIG_DIR/key.pem" -out "$CONFIG_DIR/cert.pem" -days 365 -nodes -subj "/CN=localhost"
fi
chown "$USER:$GROUP" "$CONFIG_DIR/cert.pem" "$CONFIG_DIR/key.pem"
chmod 600 "$CONFIG_DIR/cert.pem" "$CONFIG_DIR/key.pem"

# Grant CAP_NET_BIND_SERVICE capability to the binary
setcap 'cap_net_bind_service=+ep' "$INSTALL_DIR/$BINARY_NAME"

# Create systemd service file with better restart policy
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
ExecStartPre=/bin/sh -c 'echo Starting Webber > /tmp/webber.log'
Environment=DEBUG=1

[Install]
WantedBy=multi-user.target
EOF

# Enable and start service
systemctl daemon-reload
systemctl enable "$SERVICE_NAME"
systemctl start "$SERVICE_NAME"

# Check service status
if systemctl is-active "$SERVICE_NAME" >/dev/null; then
  echo "Installation complete. Service $SERVICE_NAME is running."
  echo "Access at https://localhost:443"
else
  echo "Service failed to start. Check logs with 'journalctl -u webber' or /tmp/webber.log"
  exit 1
fi
