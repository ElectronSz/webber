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

## Getting Started

### 1. **Install with `install.sh`**

The provided install script will:

- Clone the repo from GitHub.
- Build the Go binary.
- Copy configuration and static files.
- Set up systemd service and TLS certificates.

```bash
sudo ./install.sh
```

### 2. **Configuration**

Edit `/etc/webber/config.json` as needed:

```json
{
  "port": "443",
  "static_dir": "/var/www/webber",
  "proxy_targets": [
    "http://localhost:8081",
    "http://localhost:8082"
  ],
  "rate_limit_rps": 10.0,
  "rate_limit_burst": 20,
  "cache_ttl_seconds": 300
}
```

- **port**: Listening port (`443` for HTTPS)
- **static_dir**: Directory for static assets (`index.html`, JS, CSS, images)
- **proxy_targets**: Array of backend URLs for reverse proxy
- **rate_limit_rps**: Requests per second per client IP
- **rate_limit_burst**: Rate limiter burst size
- **cache_ttl_seconds**: Static file cache TTL (seconds)

---

### 3. **Deploy an SPA (Vue.js, React, Angular)**

#### **Vue.js**

1. Build your Vue.js project:

   ```bash
   npm run build
   ```

2. Copy the contents of the `dist/` folder to `/var/www/webber`:

   ```bash
   sudo cp -r dist/* /var/www/webber/
   sudo chown -R webber:webber /var/www/webber
   sudo chmod -R 755 /var/www/webber
   ```

3. Restart Webber:

   ```bash
   sudo systemctl restart webber
   ```

4. Visit [https://localhost/](https://localhost/) to see your Vue app.

#### **React**

1. Build your React project:

   ```bash
   npm run build
   ```

2. Copy the contents of the `build/` folder to `/var/www/webber`:

   ```bash
   sudo cp -r build/* /var/www/webber/
   sudo chown -R webber:webber /var/www/webber
   sudo chmod -R 755 /var/www/webber
   ```

3. Restart Webber:

   ```bash
   sudo systemctl restart webber
   ```

4. Visit [https://localhost/](https://localhost/) to see your React app.

#### **Angular**

1. Build your Angular project:

   ```bash
   ng build --prod
   ```

2. Copy the contents of the `dist/<project-name>/` folder to `/var/www/webber`:

   ```bash
   sudo cp -r dist/<project-name>/* /var/www/webber/
   sudo chown -R webber:webber /var/www/webber
   sudo chmod -R 755 /var/www/webber
   ```

3. Restart Webber:

   ```bash
   sudo systemctl restart webber
   ```

4. Visit [https://localhost/](https://localhost/) to see your Angular app.

---

## **Default Welcome Page**

The default `index.html` demonstrates Webber's features and configuration. Replace it with your SPA's build output as described above.

---

## **Static File MIME Types**

The server provides correct MIME types for all common static assets (CSS, JS, fonts, SVG, etc.) to support modern frontend builds.

---

## **TLS Certificates**

`install.sh` generates self-signed certificates if not provided. For production, replace `/etc/webber/cert.pem` and `/etc/webber/key.pem` with your own.

---

## **Service Management**

```bash
sudo systemctl status webber
sudo systemctl restart webber
sudo journalctl -u webber
```

---

## **Contributing**

PRs and issues are welcome!  
Built with ❤️ by [ElectronSz](https://github.com/ElectronSz).
