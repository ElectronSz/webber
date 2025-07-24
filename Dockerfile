# Stage 1: Builder - Downloads the binary and prepares assets
FROM alpine:latest AS builder

# Install necessary packages for downloading, certificate generation, and JSON parsing
# wget: for downloading the binary
# openssl: for generating self-signed certificates
# ca-certificates: for trust store when downloading over HTTPS
# curl: for making API requests to GitHub
# jq: for parsing JSON responses from GitHub API
RUN apk add --no-cache wget openssl ca-certificates curl jq

# Dynamically determine the latest release version of Webber from GitHub
# This command fetches the latest release JSON, parses the 'tag_name',
# and constructs the full download URL for the 'webber' binary.
ARG WEBBER_REPO="ElectronSz/webber"
ENV WEBBER_REPO=${WEBBER_REPO}
RUN LATEST_TAG=$(curl -s "https://api.github.com/repos/${WEBBER_REPO}/releases/latest" | jq -r .tag_name) \
    && echo "Detected latest Webber version: ${LATEST_TAG}" \
    && WEBBER_BINARY_URL="https://github.com/${WEBBER_REPO}/releases/download/${LATEST_TAG}/webber" \
    && echo "WEBBER_BINARY_URL=${WEBBER_BINARY_URL}" >> /tmp/webber_env.sh

# Source the environment variable for subsequent commands in this stage
RUN . /tmp/webber_env.sh

# Create a non-root user and group for security best practices
# -S: Create a system user/group
# -G: Specify the primary group
# -s /bin/false: No login shell for the user
RUN addgroup -S webber && adduser -S webber -G webber -s /bin/false

# Create necessary directories for configuration and static files
# /etc/webber: Will hold the config.json and TLS certificates
# /var/www/webber: This is where your web application's static files will reside
RUN mkdir -p /etc/webber /var/www/webber

# Download the Webber binary to a temporary directory using the dynamically determined URL
WORKDIR /tmp
RUN . /tmp/webber_env.sh \
    && wget -q -O webber "$WEBBER_BINARY_URL" \
    # Make the downloaded binary executable
    && chmod +x webber \
    # Move the binary to a standard executable path
    && mv webber /usr/local/bin/webber

# Create a default config.json file in the config directory
# This configuration can be overridden by mounting a custom config.json
WORKDIR /etc/webber
RUN cat > config.json <<EOF
{
  "port": "443",
  "static_dir": "./static",
  "proxy_targets": [],
  "rate_limit_rps": 10.0,
  "rate_limit_burst": 20,
  "cache_ttl_seconds": 300,
  "debug": false,
  "certFile": "cert.pem",
  "keyFile": "key.pem"
}
EOF

# Generate self-signed TLS certificates for HTTPS
# These are for development/testing; for production, mount your own trusted certificates.
# -x509: Output a self-signed certificate
# -newkey rsa:4096: Generate a new 4096-bit RSA private key
# -keyout: Specify output file for the private key
# -out: Specify output file for the certificate
# -days 365: Certificate validity period in days
# -nodes: Do not encrypt the private key
# -subj "/CN=localhost": Set the Common Name to localhost
RUN openssl req -x509 -newkey rsa:4096 -keyout key.pem -out cert.pem -days 365 -nodes -subj "/CN=localhost"

# Create a symbolic link from /etc/webber/static to /var/www/webber
# This is crucial because the webber binary expects 'static_dir' to be relative
# to its working directory (which will be /etc/webber).
# This allows users to mount their static content to /var/www/webber.
RUN ln -s /var/www/webber static

# Set ownership of the configuration directory and its contents to the webber user
RUN chown -R webber:webber /etc/webber

# Stage 2: Final image - Minimal runtime environment
FROM alpine:latest

# Install ca-certificates to ensure trust for outgoing HTTPS connections 
# and for the server to serve HTTPS correctly.
RUN apk add --no-cache ca-certificates libcap

# Copy the Webber binary, configuration, and static directory setup from the builder stage
COPY --from=builder /usr/local/bin/webber /usr/local/bin/webber
COPY --from=builder /etc/webber /etc/webber
# /var/www/webber will be an empty directory here, ready for mounting static content
COPY --from=builder /var/www/webber /var/www/webber

# Recreate the webber user and group in the final image
RUN addgroup -S webber && adduser -S webber -G webber -s /bin/false

# Set ownership and permissions for the binary and directories in the final image
RUN chown webber:webber /usr/local/bin/webber \
    && chmod +x /usr/local/bin/webber \
    && chown -R webber:webber /etc/webber \
    && chown -R webber:webber /var/www/webber

# Grant CAP_NET_BIND_SERVICE capability to the binary
# This allows the non-root 'webber' user to bind to privileged ports (like 443).
# libcap is installed in the previous step.
RUN setcap 'cap_net_bind_service=+ep' /usr/local/bin/webber

# Expose port 443, as configured in config.json for HTTPS
EXPOSE 443

# Set the user to run the application as
USER webber

# Set the working directory for the Webber server
# This is important because 'static_dir' in config.json is relative to this.
WORKDIR /etc/webber

# Define the command to run the Webber server when the container starts
CMD ["/usr/local/bin/webber"]
