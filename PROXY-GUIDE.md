# Webber Reverse Proxy - Testing Guide

This document demonstrates the new nginx-style reverse proxy feature in Webber.

## Configuration Options

### Option 1: Simple Single Backend (Like Caddy)

```json
{
  "port": "443",
  "static_dir": "./static",
  "proxy_mode": true,
  "proxy_backend": "http://localhost:3000",
  "rate_limit_rps": 10.0,
  "rate_limit_burst": 20,
  "cache_ttl_seconds": 300
}
```

This configuration:
- Enables reverse proxy mode (`proxy_mode: true`)
- Proxies ALL requests from root `/` to `http://localhost:3000`
- Sets proper nginx-like headers automatically

### Option 2: Load Balancing Across Multiple Backends

```json
{
  "port": "443",
  "static_dir": "./static",
  "proxy_mode": true,
  "proxy_targets": ["http://localhost:8081", "http://localhost:8082"],
  "rate_limit_rps": 10.0,
  "rate_limit_burst": 20,
  "cache_ttl_seconds": 300
}
```

This configuration:
- Enables reverse proxy mode
- Load balances requests across multiple backends in round-robin fashion
- All requests are proxied with proper headers

### Option 3: Traditional Static File Serving (Default)

```json
{
  "port": "443",
  "static_dir": "./static",
  "proxy_mode": false,
  "proxy_targets": ["http://localhost:8081"],
  "rate_limit_rps": 10.0,
  "rate_limit_burst": 20,
  "cache_ttl_seconds": 300
}
```

This configuration:
- Serves static files from `./static` directory
- Provides `/proxy` endpoint for proxying specific requests
- SPA support with fallback to index.html

## Headers Forwarded to Backend

When using reverse proxy mode, Webber automatically forwards the following headers (like nginx):

```
Host: <original-host>
X-Real-IP: <client-real-ip>
X-Forwarded-For: <chain-of-ips>
X-Forwarded-Proto: <http-or-https>
X-Forwarded-Host: <original-host-header>
```

## Comparison with Nginx

### Nginx Configuration:
```nginx
location / {
    proxy_pass http://localhost:3000;
    proxy_set_header Host $host;
    proxy_set_header X-Real-IP $remote_addr;
    proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    proxy_set_header X-Forwarded-Proto $scheme;
}
```

### Webber Configuration (Equivalent):
```json
{
  "proxy_mode": true,
  "proxy_backend": "http://localhost:3000"
}
```

Much simpler! Webber handles all the header forwarding automatically.

## Testing the Reverse Proxy

1. Start your backend application (e.g., Next.js on port 3000):
   ```bash
   npm run dev
   ```

2. Configure Webber with proxy mode:
   ```bash
   cp config-proxy-example.json config.json
   ```

3. Start Webber:
   ```bash
   ./webber
   ```

4. Access your application through Webber:
   ```bash
   curl https://localhost:443/
   ```

All requests will be proxied to your backend with proper headers!
