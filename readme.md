# Webber Web Server

Webber is a modern, high-performance Go web server inspired by Nginx, with support for static file hosting (optimized for Vue.js, React, Angular, and other SPA builds), reverse proxying, WebSocket, rate limiting, gzip compression, in-memory caching, HTTP/2, and TLS.

---

## Features

- **Logging Middleware**: Logs every HTTP request and response time.
- **Rate Limiting**: Per-client IP request limits; configure via `RateLimitRPS` and `RateLimitBurst`.
- **Gzip Compression**: Automatic gzip for clients that support it.
- **URL Rewriting**: Example: `/old/example` redirects to `/new/example`.
- **Reverse Proxy & Load Balancing**: Round-robin proxying to backend services with nginx-like headers.
- **Nginx-Style Reverse Proxy Mode**: Simple single-line configuration to proxy all requests to a backend (like Next.js, Node.js, etc.).
- **WebSocket Support**: Real-time, bidirectional communication (`/ws` endpoint).
- **Static File Serving with Caching**: Efficiently serves static assets (SPA-ready), with in-memory caching.
- **HTTP/2 and TLS**: Secure, high-performance communication by default.
- **SPA Routing Support**: Unmatched routes serve `index.html` for client-side navigation (Vue.js, React, Angular, etc.).

---

## Reverse Proxy Configuration

Webber now supports nginx-style reverse proxy configuration with proper header forwarding.

### Simple Reverse Proxy Mode

To proxy all requests to a backend service (e.g., Next.js running on port 3000):

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

This is equivalent to the Caddy configuration:
```
example.com {
  reverse_proxy localhost:3000
}
```

### Headers Forwarded

When using reverse proxy mode, Webber automatically sets the following headers (like nginx):
- `Host`: The original host header
- `X-Real-IP`: The client's real IP address
- `X-Forwarded-For`: Chain of proxied IPs
- `X-Forwarded-Proto`: Original protocol (http/https)
- `X-Forwarded-Host`: Original host requested by the client

### Load Balancing Mode

For load balancing across multiple backends:

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

---

For full documentation, visit the [Webber Documentation website](https://webber-docs.vercel.app/).

---

## **Contributing**

Contributions, bug reports, and feature requests are highly welcome!
Please feel free to [open a Pull Request (PR)](https://github.com/ElectronSz/webber/pulls) or [submit an issue](https://github.com/ElectronSz/webber/issues) on the GitHub repository.

---

Built in Eswatini with ❤️ by [ElectronSz](https://github.com/ElectronSz)
