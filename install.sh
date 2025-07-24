#!/bin/bash

# Configuration
SERVICE_NAME="webber"
BINARY_NAME="webber"
INSTALL_DIR="/usr/local/bin"
CONFIG_DIR="/etc/webber"
STATIC_SERVE_DIR="/var/www/webber" # This is where the web server will serve files from
STATIC_SOURCE_DIR="$CONFIG_DIR/static" # This is where the original static files will be stored canonically
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
mkdir -p "$STATIC_SERVE_DIR" || { echo "Failed to create static serve directory"; exit 1; }
mkdir -p "$STATIC_SOURCE_DIR" || { echo "Failed to create static source directory"; exit 1; }

# Set ownership and permissions for serving directory
chown "$USER:$GROUP" "$STATIC_SERVE_DIR"
chmod 755 "$STATIC_SERVE_DIR"

# Copy binary and config
cp "$BINARY_NAME" "$INSTALL_DIR/" || { echo "Failed to copy binary"; exit 1; }
cp config.json "$CONFIG_DIR/" || { echo "Failed to copy config"; exit 1; }
chown "$USER:$GROUP" "$CONFIG_DIR/config.json"
chmod 644 "$CONFIG_DIR/config.json"

# Copy static files from the current directory's 'static' folder
# to their canonical source location in /etc/webber/static/
if [ -d "static" ]; then
  echo "Copying static files to $STATIC_SOURCE_DIR..."
  # Use rsync for more robust copying, especially if files already exist
  rsync -av static/ "$STATIC_SOURCE_DIR/" || { echo "Failed to copy static source files"; exit 1; }
  chown -R "$USER:$GROUP" "$STATIC_SOURCE_DIR"
  chmod -R 755 "$STATIC_SOURCE_DIR"
fi

# Create symlinks from the static source directory to the serving directory
echo "Creating symlinks from $STATIC_SOURCE_DIR to $STATIC_SERVE_DIR..."

# Remove any existing files/symlinks in the STATIC_SERVE_DIR to ensure a clean slate for symlinks
# This is crucial to prevent the "same file" error if previous attempts left files behind.
rm -rf "$STATIC_SERVE_DIR"/* # Remove all contents, but not the directory itself

# Now, create the symlinks from the canonical source to the serving directory
for file in "$STATIC_SOURCE_DIR"/*; do
    if [ -e "$file" ]; then # Check if file exists to prevent errors with empty directories
        ln -sf "$file" "$STATIC_SERVE_DIR/" || { echo "Failed to create symlink for $(basename "$file")"; exit 1; }
    fi
done

# Generate self-signed certificates if not provided
if [ ! -f "$CONFIG_DIR/cert.pem" ] || [ ! -f "$CONFIG_DIR/key.pem" ]; then
  echo "Generating self-signed TLS certificates..."
  openssl req -x509 -newkey rsa:4096 -keyout "$CONFIG_DIR/key.pem" -out "$CONFIG_DIR/cert.pem" -days 365 -nodes -subj "/CN=localhost"
fi
chown "$USER:$GROUP" "$CONFIG_DIR/cert.pem" "$CONFIG_DIR/key.pem"
chmod 600 "$CONFIG_DIR/cert.pem" "$CONFIG_DIR/key.pem"

# Grant CAP_NET_BIND_SERVICE capability to the binary
# Corrected typo: 'cap_net_bind_bind_service' -> 'cap_net_bind_service'
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
echo "Reloading systemd daemon..."
systemctl daemon-reload
echo "Enabling and starting $SERVICE_NAME service..."
systemctl enable "$SERVICE_NAME"
echo "Starting $SERVICE_NAME service..."
systemctl start "$SERVICE_NAME"

# Check service status
echo "Checking service status..."
if systemctl is-active "$SERVICE_NAME" >/dev/null; then
  echo "Installation complete. Service $SERVICE_NAME is running."
  echo "Access at https://localhost:443"
else
  echo "Service failed to start. Check logs with 'journalctl -u webber' or /tmp/webber.log"
  exit 1
fi
echo "Webber web server installed successfully."
