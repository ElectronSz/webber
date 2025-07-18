package main

import (
	"compress/gzip"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/gorilla/mux"
	"github.com/gorilla/websocket"
	"golang.org/x/net/http2"
	"golang.org/x/time/rate"
)

// GlobalSettings for server-wide configurations
type GlobalSettings struct {
	LogLevel              string `json:"log_level"`
	DefaultRateLimitRPS   float64 `json:"default_rate_limit_rps"`
	DefaultRateLimitBurst int     `json:"default_rate_limit_burst"`
}

// TLSConfig for site-specific TLS settings
type TLSConfig struct {
	Enabled         bool   `json:"enabled"`
	CertificateFile string `json:"certificate_file"`
	PrivateKeyFile  string `json:"private_key_file"`
}

// Route defines how a specific URL path should be handled
type Route struct {
	Path                  string   `json:"path"`
	Type                  string   `json:"type"` // e.g., "static", "proxy", "websocket", "redirect", "regex"
	RootDir               string   `json:"root_dir"` // For static
	CacheTTLSeconds       int      `json:"cache_ttl_seconds"` // For static
	ProxyTargets          []string `json:"proxy_targets"` // For proxy
	LoadBalancingStrategy string   `json:"load_balancing_strategy"` // For proxy (e.g., "round_robin", "least_connections")
	Target                string   `json:"target"` // For redirect
	StatusCode            int      `json:"status_code"` // For redirect (e.g., 301, 302)
	Regex                 string   `json:"regex"` // For regex type routes
	AllowedMethods        []string `json:"allowed_methods"` // For advanced routing (e.g., ["GET", "POST"])
}

// MiddlewareConfig defines middleware settings for a site or route
type MiddlewareConfig struct {
	Logging          bool                    `json:"logging"`
	RateLimiting     *RateLimitingConfig     `json:"rate_limiting"`
	GzipCompression  bool                    `json:"gzip_compression"`
	URLRewriting     bool                    `json:"url_rewriting"` // Simple rewrite (like /old to /new)
	SecurityHeaders  *SecurityHeadersConfig  `json:"security_headers"`
	CORS             *CORSConfig             `json:"cors"`
	IPAccessControl  *IPAccessControlConfig  `json:"ip_access_control"`
	BasicAuth        *BasicAuthConfig        `json:"basic_auth"`
	RequestBodyLimit *RequestBodyLimitConfig `json:"request_body_limit"`
}

// RateLimitingConfig for per-site/per-route rate limiting overrides
type RateLimitingConfig struct {
	Enabled bool    `json:"enabled"`
	RPS     float64 `json:"rps"`
	Burst   int     `json:"burst"`
}

// SecurityHeadersConfig for HTTP security headers
type SecurityHeadersConfig struct {
	Enabled                       bool   `json:"enabled"`
	HSTSMaxAge                    int    `json:"hsts_max_age"` // e.g., 31536000 for 1 year
	ContentSecurityPolicy         string `json:"content_security_policy"` // e.g., "default-src 'self'"
	XContentTypeOptions           bool   `json:"x_content_type_options"` // X-Content-Type-Options: nosniff
	XFrameOptions                 string `json:"x_frame_options"` // e.g., "DENY", "SAMEORIGIN"
	XPermittedCrossDomainPolicies string `json:"x_permitted_cross_domain_policies"` // e.g., "none"
	ReferrerPolicy                string `json:"referrer_policy"` // e.g., "no-referrer-when-downgrade"
}

// CORSConfig for Cross-Origin Resource Sharing
type CORSConfig struct {
	Enabled          bool     `json:"enabled"`
	AllowOrigins     []string `json:"allow_origins"`
	AllowMethods     []string `json:"allow_methods"`
	AllowHeaders     []string `json:"allow_headers"`
	ExposeHeaders    []string `json:"expose_headers"`
	AllowCredentials bool     `json:"allow_credentials"`
	MaxAge           int      `json:"max_age"` // seconds
}

// IPAccessControlConfig for IP whitelisting/blacklisting
type IPAccessControlConfig struct {
	Enabled     bool     `json:"enabled"`
	Whitelist   []string `json:"whitelist"` // List of IPs or CIDR blocks
	Blacklist   []string `json:"blacklist"` // List of IPs or CIDR blocks
	DefaultDeny bool     `json:"default_deny"` // If true, only whitelist is allowed
}

// BasicAuthConfig for simple username/password authentication
type BasicAuthConfig struct {
	Enabled bool              `json:"enabled"`
	Users   map[string]string `json:"users"` // map of username -> hashed_password (for production, use bcrypt)
	Realm   string            `json:"realm"`
}

// RequestBodyLimitConfig for limiting request body size
type RequestBodyLimitConfig struct {
	Enabled   bool `json:"enabled"`
	MaxSizeMB int  `json:"max_size_mb"` // Max size in megabytes
}

// Site represents a single virtual host configuration
type Site struct {
	ServerNames  []string          `json:"server_names"` // Hostnames for this site
	ListenPorts  []string          `json:"listen_ports"` // Ports this site listens on
	TLS          *TLSConfig        `json:"tls"`
	HTTP2Enabled bool              `json:"http2_enabled"`
	Routes       []Route           `json:"routes"`
	Middleware   *MiddlewareConfig `json:"middleware"`
}

// Config struct for the entire server configuration
type Config struct {
	GlobalSettings GlobalSettings `json:"global_settings"`
	Sites          []Site         `json:"sites"`
}

// --- Existing Structs (Unchanged) ---

// RateLimiter for per-client IP rate limiting
type RateLimiter struct {
	limiters map[string]*rate.Limiter
	mu       sync.Mutex
	r        rate.Limit
	b        int
}

// NewRateLimiter creates and returns a new RateLimiter instance.
func NewRateLimiter(r rate.Limit, b int) *RateLimiter {
	return &RateLimiter{
		limiters: make(map[string]*rate.Limiter),
		r:        r,
		b:        b,
	}
}

// GetLimiter retrieves or creates a rate.Limiter for a given IP address.
func (rl *RateLimiter) GetLimiter(ip string) *rate.Limiter {
	rl.mu.Lock()
	defer rl.mu.Unlock()
	limiter, exists := rl.limiters[ip]
	if !exists {
		limiter = rate.NewLimiter(rl.r, rl.b)
		rl.limiters[ip] = limiter
	}
	return limiter
}

// LoadBalancer for round-robin load balancing
type LoadBalancer struct {
	servers []string
	current uint64
}

// NewLoadBalancer creates and returns a new LoadBalancer instance.
func NewLoadBalancer(servers []string) *LoadBalancer {
	return &LoadBalancer{servers: servers}
}

// NextServer returns the next server URL in a round-robin fashion.
func (lb *LoadBalancer) NextServer() string {
	// Atomically increment the counter and get the next server.
	server := lb.servers[atomic.AddUint64(&lb.current, 1)%uint64(len(lb.servers))]
	return server
}

// CacheEntry for storing cached responses
type CacheEntry struct {
	Body     []byte
	Expires  time.Time
	Headers  http.Header
	MimeType string
}

// Cache for storing static file responses
type Cache struct {
	store map[string]*CacheEntry
	mu    sync.RWMutex
	ttl   time.Duration
}

// NewCache creates and returns a new Cache instance with a given TTL.
func NewCache(ttl time.Duration) *Cache {
	return &Cache{
		store: make(map[string]*CacheEntry),
		ttl:   ttl,
	}
}

// Get retrieves a CacheEntry from the cache if it exists and has not expired.
func (c *Cache) Get(key string) (*CacheEntry, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	entry, exists := c.store[key]
	if exists && time.Now().Before(entry.Expires) {
		return entry, true
	}
	return nil, false
}

// Set adds or updates a CacheEntry in the cache.
func (c *Cache) Set(key string, body []byte, headers http.Header, mimeType string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.store[key] = &CacheEntry{
		Body:     body,
		Expires:  time.Now().Add(c.ttl),
		Headers:  headers,
		MimeType: mimeType,
	}
}

// GzipResponseWriter for gzip compression
type GzipResponseWriter struct {
	io.Writer
	http.ResponseWriter
}

// Write implements the io.Writer interface for GzipResponseWriter.
func (w GzipResponseWriter) Write(b []byte) (int, error) {
	return w.Writer.Write(b)
}

// WebSocket upgrader
var upgrader = websocket.Upgrader{
	ReadBufferSize:  1024,
	WriteBufferSize: 1024,
	CheckOrigin:     func(r *http.Request) bool { return true }, // Allow all origins for simplicity in development
}

// --- Middleware Functions (Adapted and New) ---

// loggingMiddleware logs details about each incoming HTTP request.
func loggingMiddleware(next http.Handler, enabled bool) http.Handler {
	if !enabled {
		return next
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		log.Printf("Request: %s %s from %s", r.Method, r.RequestURI, r.RemoteAddr)
		next.ServeHTTP(w, r)
		log.Printf("Response: %s %s completed in %v", r.Method, r.RequestURI, time.Since(start))
	})
}

// rateLimitMiddleware applies per-client IP rate limiting.
func rateLimitMiddleware(rl *RateLimiter, config *RateLimitingConfig) mux.MiddlewareFunc {
	if config == nil || !config.Enabled {
		return func(next http.Handler) http.Handler { return next } // No-op if disabled
	}
	effectiveRPS := rate.Limit(config.RPS)
	effectiveBurst := config.Burst

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ip := r.RemoteAddr // Consider `r.Header.Get("X-Forwarded-For")` in production behind a proxy
			limiter := rl.GetLimiter(ip) // Gets a global limiter for the IP

			// Dynamically set limiter rate if different from global default or previous site's config
			// This allows per-site rate limiting to adjust the shared limiter.
			if limiter.Limit() != effectiveRPS || limiter.Burst() != effectiveBurst {
				limiter.SetLimit(effectiveRPS)
				limiter.SetBurst(effectiveBurst)
			}

			if !limiter.Allow() {
				log.Printf("Rate limit exceeded for IP: %s (RPS: %.2f, Burst: %d)", ip, effectiveRPS, effectiveBurst)
				http.Error(w, "Rate limit exceeded", http.StatusTooManyRequests)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

// gzipMiddleware compresses responses if the client supports gzip encoding.
func gzipMiddleware(next http.Handler, enabled bool) http.Handler {
	if !enabled {
		return next
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Skip compression for WebSocket requests
		if strings.Contains(r.Header.Get("Connection"), "Upgrade") && strings.Contains(r.Header.Get("Upgrade"), "websocket") {
			next.ServeHTTP(w, r)
			return
		}
		// Check if client supports gzip
		if !strings.Contains(r.Header.Get("Accept-Encoding"), "gzip") {
			next.ServeHTTP(w, r)
			return
		}
		// Set the Content-Encoding header
		w.Header().Set("Content-Encoding", "gzip")
		// Create a new gzip writer
		gz, err := gzip.NewWriterLevel(w, gzip.BestSpeed)
		if err != nil {
			log.Printf("Failed to create gzip writer: %v", err)
			http.Error(w, "Internal Server Error", http.StatusInternalServerError)
			return
		}
		defer gz.Close()
		// Wrap the response writer
		gzw := GzipResponseWriter{Writer: gz, ResponseWriter: w}
		next.ServeHTTP(gzw, r)
	})
}

// rewriteMiddleware demonstrates URL rewriting/redirection.
// This is a simple example; for true regex rewrites, use a dedicated regex router.
func rewriteMiddleware(next http.Handler, enabled bool) http.Handler {
	if !enabled {
		return next
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Example: Permanent redirect from /old-path to /new-path
		if r.URL.Path == "/old-path" {
			http.Redirect(w, r, "/new-path", http.StatusMovedPermanently)
			log.Printf("Rewriting %s to /new-path (redirect)", r.URL.Path)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// securityHeadersMiddleware adds various HTTP security headers.
func securityHeadersMiddleware(next http.Handler, config *SecurityHeadersConfig) http.Handler {
	if config == nil || !config.Enabled {
		return next
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if config.HSTSMaxAge > 0 {
			w.Header().Set("Strict-Transport-Security", fmt.Sprintf("max-age=%d; includeSubDomains", config.HSTSMaxAge))
		}
		if config.ContentSecurityPolicy != "" {
			w.Header().Set("Content-Security-Policy", config.ContentSecurityPolicy)
		}
		if config.XContentTypeOptions {
			w.Header().Set("X-Content-Type-Options", "nosniff")
		}
		if config.XFrameOptions != "" {
			w.Header().Set("X-Frame-Options", config.XFrameOptions)
		}
		if config.XPermittedCrossDomainPolicies != "" {
			w.Header().Set("X-Permitted-Cross-Domain-Policies", config.XPermittedCrossDomainPolicies)
		}
		if config.ReferrerPolicy != "" {
			w.Header().Set("Referrer-Policy", config.ReferrerPolicy)
		}
		next.ServeHTTP(w, r)
	})
}

// corsMiddleware handles Cross-Origin Resource Sharing.
func corsMiddleware(next http.Handler, config *CORSConfig) http.Handler {
	if config == nil || !config.Enabled {
		return next
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		origin := r.Header.Get("Origin")
		if origin != "" {
			allowed := false
			for _, ao := range config.AllowOrigins {
				if ao == "*" || ao == origin {
					allowed = true
					break
				}
			}
			if allowed {
				w.Header().Set("Access-Control-Allow-Origin", origin)
				if config.AllowCredentials {
					w.Header().Set("Access-Control-Allow-Credentials", "true")
				}
				if r.Method == "OPTIONS" {
					w.Header().Set("Access-Control-Allow-Methods", strings.Join(config.AllowMethods, ", "))
					w.Header().Set("Access-Control-Allow-Headers", strings.Join(config.AllowHeaders, ", "))
					if config.MaxAge > 0 {
						w.Header().Set("Access-Control-Max-Age", fmt.Sprintf("%d", config.MaxAge))
					}
					w.WriteHeader(http.StatusNoContent)
					return
				}
			}
		}
		next.ServeHTTP(w, r)
	})
}

// ipAccessControlMiddleware filters requests based on IP whitelist/blacklist.
func ipAccessControlMiddleware(next http.Handler, config *IPAccessControlConfig) http.Handler {
	if config == nil || !config.Enabled {
		return next
	}

	// For production, parse CIDR blocks using net.ParseCIDR and use ipNet.Contains(ipAddr)
	// For this example, we'll do basic string matching.

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		clientIP := strings.Split(r.RemoteAddr, ":")[0] // Get just the IP address

		isWhitelisted := false
		if len(config.Whitelist) > 0 {
			for _, ip := range config.Whitelist {
				if clientIP == ip {
					isWhitelisted = true
					break
				}
			}
		}

		isBlacklisted := false
		if len(config.Blacklist) > 0 {
			for _, ip := range config.Blacklist {
				if clientIP == ip {
					isBlacklisted = true
					break
				}
			}
		}

		if isBlacklisted {
			log.Printf("IP Blacklisted: %s for %s", clientIP, r.RequestURI)
			http.Error(w, "Forbidden", http.StatusForbidden)
			return
		}

		if config.DefaultDeny && !isWhitelisted {
			log.Printf("IP Not Whitelisted (Default Deny): %s for %s", clientIP, r.RequestURI)
			http.Error(w, "Forbidden", http.StatusForbidden)
			return
		}

		next.ServeHTTP(w, r)
	})
}

// basicAuthMiddleware implements HTTP Basic Authentication.
func basicAuthMiddleware(next http.Handler, config *BasicAuthConfig) http.Handler {
	if config == nil || !config.Enabled {
		return next
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		user, pass, ok := r.BasicAuth()
		if !ok || config.Users[user] != pass { // In production, hash passwords (e.g., bcrypt)
			w.Header().Set("WWW-Authenticate", fmt.Sprintf(`Basic realm="%s"`, config.Realm))
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// requestBodyLimitMiddleware limits the size of the request body.
func requestBodyLimitMiddleware(next http.Handler, config *RequestBodyLimitConfig) http.Handler {
	if config == nil || !config.Enabled || config.MaxSizeMB <= 0 {
		return next
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r.Body = http.MaxBytesReader(w, r.Body, int64(config.MaxSizeMB)*1024*1024) // MB to bytes
		next.ServeHTTP(w, r)
	})
}

// --- Handler Functions (Adapted) ---

// reverseProxyHandler proxies requests to a backend server selected by the LoadBalancer.
func reverseProxyHandler(lb *LoadBalancer, allowedMethods []string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if len(allowedMethods) > 0 && !contains(allowedMethods, r.Method) {
			http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
			return
		}

		target := lb.NextServer()
		url, err := url.Parse(target)
		if err != nil {
			log.Printf("Error parsing proxy target URL %s: %v", target, err)
			http.Error(w, "Bad gateway", http.StatusBadGateway)
			return
		}
		proxy := httputil.NewSingleHostReverseProxy(url)
		// Modify the response to remove existing Content-Encoding
		proxy.ModifyResponse = func(resp *http.Response) error {
			resp.Header.Del("Content-Encoding") // Remove backend's Content-Encoding to avoid conflicts
			return nil
		}
		r.Host = url.Host
		r.URL.Host = url.Host
		r.URL.Scheme = url.Scheme
		log.Printf("Proxying request %s to %s", r.URL.Path, target)
		proxy.ServeHTTP(w, r)
	}
}

// webSocketHandler handles WebSocket connections, echoing messages back.
func webSocketHandler(w http.ResponseWriter, r *http.Request, allowedMethods []string) {
	if len(allowedMethods) > 0 && !contains(allowedMethods, r.Method) {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}

	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		log.Printf("WebSocket upgrade failed: %v", err)
		http.Error(w, "WebSocket upgrade failed", http.StatusBadRequest)
		return
	}
	defer conn.Close()
	log.Printf("WebSocket connection established with %s", r.RemoteAddr)

	for {
		messageType, p, err := conn.ReadMessage()
		if err != nil {
			log.Printf("WebSocket read error from %s: %v", r.RemoteAddr, err)
			return // Exit on read error (e.g., client disconnected)
		}
		log.Printf("Received WebSocket message from %s (type %d): %s", r.RemoteAddr, messageType, string(p))
		if err := conn.WriteMessage(messageType, p); err != nil {
			log.Printf("WebSocket write error to %s: %v", r.RemoteAddr, err)
			return // Exit on write error
		}
	}
}

// staticFileHandler serves static files from a directory with in-memory caching.
func staticFileHandler(staticDir string, cache *Cache, allowedMethods []string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if len(allowedMethods) > 0 && !contains(allowedMethods, r.Method) {
			http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
			return
		}

		requestedPath := filepath.Clean(r.URL.Path)
		if strings.Contains(requestedPath, "..") {
			http.Error(w, "Forbidden", http.StatusForbidden)
			log.Printf("Forbidden: Directory traversal attempt for path: %s", r.URL.Path)
			return
		}
		fullPath := filepath.Join(staticDir, requestedPath)
		fi, err := os.Stat(fullPath)
		if err == nil && fi.IsDir() {
			fullPath = filepath.Join(fullPath, "index.html")
			requestedPath = filepath.Join(requestedPath, "index.html")
			log.Printf("Serving index.html for directory request: %s -> %s", r.URL.Path, fullPath)
		}
		cacheKey := requestedPath
		if entry, found := cache.Get(cacheKey); found {
			for k, v := range entry.Headers {
				if k != "Content-Encoding" { // Skip Content-Encoding to avoid conflicts
					for _, val := range v {
						w.Header().Add(k, val)
					}
				}
			}
			w.Header().Set("Content-Type", entry.MimeType)
			w.Write(entry.Body)
			log.Printf("Served %s from cache", requestedPath)
			return
		}
		f, err := os.Open(fullPath)
		if err != nil {
			if os.IsNotExist(err) {
				serveErrorPage(w, r, http.StatusNotFound, "File Not Found", nil)
				log.Printf("File not found: %s", fullPath)
			} else {
				http.Error(w, "Error opening file", http.StatusInternalServerError)
				log.Printf("Error opening file %s: %v", fullPath, err)
			}
			return
		}
		defer f.Close()
		body, err := io.ReadAll(f)
		if err != nil {
			http.Error(w, "Error reading file", http.StatusInternalServerError)
			log.Printf("Error reading file %s: %v", fullPath, err)
			return
		}
		mimeType := http.DetectContentType(body)
		w.Header().Set("Content-Type", mimeType)
		w.Write(body)
		headersToCache := make(http.Header)
		for k, v := range w.Header() {
			if k != "Content-Encoding" { // Exclude Content-Encoding from cache
				headersToCache[k] = v
			}
		}
		cache.Set(cacheKey, body, headersToCache, mimeType)
		log.Printf("Served %s and cached for future requests", requestedPath)
	})
}

// redirectHandler performs HTTP redirects.
func redirectHandler(target string, statusCode int, allowedMethods []string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if len(allowedMethods) > 0 && !contains(allowedMethods, r.Method) {
			http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
			return
		}
		http.Redirect(w, r, target, statusCode)
		log.Printf("Redirecting %s to %s with status %d", r.URL.Path, target, statusCode)
	}
}

// regexHandler is a placeholder for a handler that would respond to a regex match.
// In a real scenario, you'd extract parameters from the regex using gorilla/mux.Vars(r).
func regexHandler(regex string, allowedMethods []string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if len(allowedMethods) > 0 && !contains(allowedMethods, r.Method) {
			http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
			return
		}
		fmt.Fprintf(w, "Hello from Regex Route! Matched: %s with regex: %s", r.URL.Path, regex)
		log.Printf("Matched regex route: %s with path %s", regex, r.URL.Path)
	}
}

// serveErrorPage serves a custom error page for a given status code.
// For simplicity, it just writes a basic message. In a real app, it would read from a file.
func serveErrorPage(w http.ResponseWriter, r *http.Request, statusCode int, message string, err error) {
	w.WriteHeader(statusCode)
	fmt.Fprintf(w, `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Error %d - %s</title>
    <style>
        body { font-family: sans-serif; text-align: center; margin-top: 50px; }
        h1 { color: #dc3545; }
    </style>
</head>
<body>
    <h1>Error %d</h1>
    <p>%s</p>
    <p>Please try again later.</p>
</body>
</html>`, statusCode, message, statusCode, message)
	log.Printf("Served error page: %d %s for %s. Error: %v", statusCode, message, r.RequestURI, err)
}

// Helper to check if a string is in a slice.
func contains(s []string, e string) bool {
	for _, a := range s {
		if a == e {
			return true
		}
	}
	return false
}

// --- Main Function (Refactored for Multi-Site) ---

func main() {
	log.SetFlags(log.Ldate | log.Ltime | log.Lshortfile)

	// Load configuration from config.json
	configFile, err := os.ReadFile("config.json")
	if err != nil {
		log.Fatalf("Failed to read config.json: %v", err)
	}
	var config Config
	if err := json.Unmarshal(configFile, &config); err != nil {
		log.Fatalf("Failed to parse config.json: %v", err)
	}

	// Initialize global rate limiter (can be overridden per site)
	globalRateLimiter := NewRateLimiter(
		rate.Limit(config.GlobalSettings.DefaultRateLimitRPS),
		config.GlobalSettings.DefaultRateLimitBurst,
	)

	// Main router that dispatches requests to site-specific routers based on Host header
	rootRouter := mux.NewRouter()
	siteRouters := make(map[string]*mux.Router) // Map hostname to site router

	// Global caches for static files (one cache per unique root_dir, if desired)
	staticFileCaches := make(map[string]*Cache) // Map static_dir to its cache

	// Iterate through each site defined in the configuration
	for _, site := range config.Sites {
		// Create a subrouter for each site, matching its server names
		// The Host() matcher allows Gorilla Mux to dispatch based on the HTTP Host header.
		siteRouter := mux.NewRouter().Host(strings.Join(site.ServerNames, "|")).Subrouter()

		// Apply site-specific middlewares. Order matters!
		// General order: Logging -> Security Headers -> CORS -> IP Access -> Basic Auth -> Rate Limit -> Request Body Limit -> Gzip -> URL Rewriting
		if site.Middleware != nil {
			siteRouter.Use(loggingMiddleware(nil, site.Middleware.Logging))
			siteRouter.Use(securityHeadersMiddleware(nil, site.Middleware.SecurityHeaders))
			siteRouter.Use(corsMiddleware(nil, site.Middleware.CORS))
			siteRouter.Use(ipAccessControlMiddleware(nil, site.Middleware.IPAccessControl))
			siteRouter.Use(basicAuthMiddleware(nil, site.Middleware.BasicAuth))
			siteRouter.Use(rateLimitMiddleware(globalRateLimiter, site.Middleware.RateLimiting))
			siteRouter.Use(requestBodyLimitMiddleware(nil, site.Middleware.RequestBodyLimit))
			siteRouter.Use(gzipMiddleware(nil, site.Middleware.GzipCompression))
			siteRouter.Use(rewriteMiddleware(nil, site.Middleware.URLRewriting)) // Simple rewrite middleware
		}

		// Register routes for the current site
		for _, route := range site.Routes {
			var handler http.Handler
			var lb *LoadBalancer // LoadBalancer per proxy route

			// Initialize static file cache if not already present for this root_dir
			if route.Type == "static" {
				if _, ok := staticFileCaches[route.RootDir]; !ok {
					// Use site's cache TTL if provided, otherwise default to 300
					ttl := time.Duration(300) * time.Second
					if route.CacheTTLSeconds > 0 {
						ttl = time.Duration(route.CacheTTLSeconds) * time.Second
					}
					staticFileCaches[route.RootDir] = NewCache(ttl)
				}
			}

			// Determine handler based on route type
			switch route.Type {
			case "static":
				// For root path, staticFileHandler needs adjusted path internally
				if route.Path == "/" {
					handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
						originalPath := r.URL.Path
						if originalPath == "/" {
							r.URL.Path = "index.html" // Default to index.html for root path
						}
						staticFileHandler(route.RootDir, staticFileCaches[route.RootDir], route.AllowedMethods).ServeHTTP(w, r)
						r.URL.Path = originalPath // Restore original path
					})
				} else {
					// For other static paths, use http.StripPrefix
					handler = http.StripPrefix(route.Path, staticFileHandler(route.RootDir, staticFileCaches[route.RootDir], route.AllowedMethods))
				}
			case "proxy":
				if len(route.ProxyTargets) == 0 {
					log.Fatalf("Proxy route for path %s has no proxy_targets defined in site %v", route.Path, site.ServerNames)
				}
				lb = NewLoadBalancer(route.ProxyTargets) // New LoadBalancer for this specific proxy route
				handler = reverseProxyHandler(lb, route.AllowedMethods)
			case "websocket":
				handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					webSocketHandler(w, r, route.AllowedMethods)
				})
			case "redirect":
				if route.Target == "" || route.StatusCode == 0 {
					log.Fatalf("Redirect route for path %s requires 'target' and 'status_code' in site %v", route.Path, site.ServerNames)
				}
				handler = redirectHandler(route.Target, route.StatusCode, route.AllowedMethods)
			case "regex":
				if route.Regex == "" {
					log.Fatalf("Regex route for path %s requires 'regex' field in site %v", route.Path, site.ServerNames)
				}
				// Gorilla Mux's Path or PathPrefix supports regex directly.
				// We'll use Path() for exact regex matches.
				handler = regexHandler(route.Regex, route.AllowedMethods)
			default:
				log.Fatalf("Unknown route type '%s' for path '%s' in site %v", route.Type, route.Path, site.ServerNames)
			}

			// Register the handler with Gorilla Mux based on type
			if route.Type == "regex" {
				siteRouter.Path(route.Regex).Handler(handler)
			} else {
				siteRouter.PathPrefix(route.Path).Handler(handler)
			}
		}

		// Add the site's router to the root router for host-based dispatching
		rootRouter.Handle("/{path:.*}", siteRouter) // This line adds the siteRouter as a handler for any path
	}

	// Determine the main listening port(s) - for simplicity, we'll use the first site's first port.
	// For production, you might want to gather all unique ports across all sites and
	// start multiple `http.Server` instances, or use a custom `tls.Config` for SNI.
	var listenPort string
	if len(config.Sites) > 0 && len(config.Sites[0].ListenPorts) > 0 {
		listenPort = config.Sites[0].ListenPorts[0]
	} else {
		log.Fatal("No listen ports defined in config. Exiting.")
	}

	server := &http.Server{
		Addr:         ":" + listenPort,
		Handler:      rootRouter, // Use the root router that dispatches to site-specific routers
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 10 * time.Second,
	}

	// Enable HTTP/2 for the server. This is a server-wide setting when using ListenAndServeTLS.
	http2.ConfigureServer(server, &http2.Server{})

	// TLS Certificate Setup (Simplified: uses global certs for now)
	// For true per-site TLS with different certificates on the same port,
	// you would need to configure `server.TLSConfig.GetCertificate` to return
	// the correct certificate based on the `ClientHelloInfo.ServerName`.
	certFile := "cert.pem"
	keyFile := "key.pem"

	_, errCert := os.Stat(certFile)
	_, errKey := os.Stat(keyFile)

	if os.IsNotExist(errCert) || os.IsNotExist(errKey) {
		log.Println("TLS certs (cert.pem and key.pem) not found.")
		generateSelfSignedCert() // This function will log instructions and exit.
	}

	log.Printf("Tornado Web Server starting on :%s with TLS and HTTP/2 support (per-site config enabled, using global certs for now).", listenPort)
	if err := server.ListenAndServeTLS(certFile, keyFile); err != nil {
		log.Fatalf("Tornado Web Server failed to start: %v", err)
	}
}

// generateSelfSignedCert provides instructions for generating self-signed TLS certificates
// and then exits the program. This is for development/testing purposes.
func generateSelfSignedCert() {
	log.Println("To enable HTTPS, please generate self-signed certificates 'cert.pem' and 'key.pem'.")
	log.Println("You can use OpenSSL with the following command:")
	log.Println("  openssl req -x509 -newkey rsa:4096 -keyout key.pem -out cert.pem -days 365 -nodes")
	log.Println("  (When prompted, for 'Common Name (e.g. server FQDN or YOUR name)', use 'localhost' or your site's server_name for local testing.)")
	os.Exit(1) // Exit as server cannot start without certs for TLS
}
