# Webber Web Server

Webber is a modern, high-performance Go web server inspired by Nginx, with support for static file hosting (optimized for Vue.js, React, Angular, and other SPA builds), reverse proxying, WebSocket, rate limiting, gzip compression, in-memory caching, HTTP/2, and TLS.

---

## Features

- **Logging Middleware**: Logs every HTTP request and response time.
- **Rate Limiting**: Per-client IP request limits; configure via `RateLimitRPS` and `RateLimitBurst`.
- **Gzip Compression**: Automatic gzip for clients that support it.
- **URL Rewriting**: Example: `/old/example` redirects to `/new/example`.
- **Reverse Proxy & Load Balancing**: Round-robin proxying to backend services.
- **WebSocket Support**: Real-time, bidirectional communication (`/ws` endpoint).
- **Static File Serving with Caching**: Efficiently serves static assets (SPA-ready), with in-memory caching.
- **HTTP/2 and TLS**: Secure, high-performance communication by default.
- **SPA Routing Support**: Unmatched routes serve `index.html` for client-side navigation (Vue.js, React, Angular, etc.).

---

For full documentation, visit the [Webber Documentation website](https://webber-docs.vercel.app/).

---

## **Contributing**

Contributions, bug reports, and feature requests are highly welcome!
Please feel free to [open a Pull Request (PR)](https://github.com/ElectronSz/webber/pulls) or [submit an issue](https://github.com/ElectronSz/webber/issues) on the GitHub repository.

---

Built in Eswatini with ❤️ by [ElectronSz](https://github.com/ElectronSz)
