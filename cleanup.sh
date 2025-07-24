# Stop and disable the service if it's running
sudo systemctl stop webber.service || true
sudo systemctl disable webber.service || true

# Remove the systemd service file
sudo rm -f /etc/systemd/system/webber.service
sudo systemctl daemon-reload # Reload systemd to recognize changes

# Remove the Webber binary
sudo rm -f /usr/local/bin/webber

# Remove the entire Webber configuration directory and its contents
sudo rm -rf /etc/webber

# Remove the entire static serving directory and its contents
sudo rm -rf /var/www/webber

echo "Cleanup complete. You can now run the modified install.sh script."
