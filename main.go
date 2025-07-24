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

// Config struct for server configuration
type Config struct {
	Port            string   `json:"port"`
	StaticDir       string   `json:"static_dir"`
	ProxyTargets    []string `json:"proxy_targets"`
	RateLimitRPS    float64  `json:"rate_limit_rps"`
	RateLimitBurst  int      `json:"rate_limit_burst"`
	CacheTTLSeconds int      `json:"cache_ttl_seconds"`
}

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

// MimeTypeMap stores common MIME types by file extension.
var MimeTypeMap = map[string]string{
	".html": "text/html; charset=utf-8",
	".css":  "text/css; charset=utf-8",
	".js":   "application/javascript; charset=utf-8",
	".json": "application/json; charset=utf-8",
	".png":  "image/png",
	".jpg":  "image/jpeg",
	".jpeg": "image/jpeg",
	".gif":  "image/gif",
	".svg":  "image/svg+xml",
	".ico":  "image/x-icon",
	".woff": "font/woff",
	".woff2": "font/woff2",
	".ttf":  "font/ttf",
	".eot":  "application/vnd.ms-fontobject",
	".otf":  "font/otf",
	".webp": "image/webp",
	".mp3":  "audio/mpeg",
	".wav":  "audio/wav",
	".ogg":  "application/ogg", // For audio/video
	".mp4":  "video/mp4",
	".webm": "video/webm",
	".pdf":  "application/pdf",
	".xml":  "application/xml; charset=utf-8", // Consolidated XML
	".txt":  "text/plain; charset=utf-8",    // Consolidated TXT
	".csv":  "text/csv; charset=utf-8",
	".zip":  "application/zip",
	".tar":  "application/x-tar",
	".gz":   "application/gzip",
	".rar":  "application/x-rar-compressed",
	".7z":   "application/x-7z-compressed",
	".doc":  "application/msword",
	".docx": "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
	".xls":  "application/vnd.ms-excel",
	".xlsx": "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
	".ppt":  "application/vnd.ms-powerpoint",
	".pptx": "application/vnd.openxmlformats-officedocument.presentationml.presentation",
	".md":   "text/markdown; charset=utf-8",
	".xsl":  "application/xml; charset=utf-8",
	".xsd":  "application/xml; charset=utf-8",
	".yaml": "application/x-yaml; charset=utf-8",
	".yml":  "application/x-yaml; charset=utf-8",
	".toml": "application/toml; charset=utf-8",
	".wasm": "application/wasm",
	".webmanifest": "application/manifest+json",
	".appcache":    "text/cache-manifest",
	".atom":        "application/atom+xml",
	".rss":         "application/rss+xml",
	".xhtml":       "application/xhtml+xml",
	".xht":         "application/xhtml+xml",
	".vtt":         "text/vtt; charset=utf-8",
	".srt":         "application/x-subrip",
	".ics":         "text/calendar",
	".jsonld":      "application/ld+json",
	".geojson":     "application/geo+json",
	".gpx":         "application/gpx+xml",
	".kml":         "application/vnd.google-earth.kml+xml",
	".kmz":         "application/vnd.google-earth.kmz",
	".unityweb":    "application/vnd.unity",
	".glsl":        "text/plain; charset=utf-8", // Common for shader files
	".vert":        "text/plain; charset=utf-8", // Common for vertex shaders
	".frag":        "text/plain; charset=utf-8", // Common for fragment shaders
	".obj":         "application/octet-stream", // 3D model data
	".mtl":         "text/plain; charset=utf-8", // Material for 3D models
	".fbx":         "application/octet-stream", // Autodesk FBX
	".gltf":        "model/gltf+json",
	".glb":         "model/gltf-binary",
	".bin":         "application/octet-stream", // Binary data, often with glTF
	".stl":         "application/vnd.ms-pki.stl",
	".dae":         "application/xml", // Collada
	".blend":       "application/octet-stream", // Blender file
	".exr":         "image/x-exr",
	".hdr":         "image/vnd.radiance",
	".psd":         "image/vnd.adobe.photoshop",
	".ai":          "application/postscript",
	".eps":         "application/postscript",
	".dxf":         "image/vnd.dxf",
	".dwg":         "image/vnd.dwg",
	".step":        "application/step",
	".stp":         "application/step",
	".iges":        "application/iges",
	".igs":         "application/iges",
	".x3d":         "application/vnd.hzn-3d-crossword",
	".x3dv":        "application/vnd.hzn-3d-crossword",
	".x3db":        "application/vnd.hzn-3d-crossword",
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
		Body:    body,
		Expires: time.Now().Add(c.ttl),
		Headers: headers,
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
	CheckOrigin:     func(r *http.Request) bool { return true },
}

// loggingMiddleware logs details about each incoming HTTP request.
func loggingMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		log.Printf("Request: %s %s from %s", r.Method, r.RequestURI, r.RemoteAddr)
		next.ServeHTTP(w, r)
		log.Printf("Response: %s %s completed in %v", r.Method, r.RequestURI, time.Since(start))
	})
}

// rateLimitMiddleware applies per-client IP rate limiting.
func rateLimitMiddleware(rl *RateLimiter) mux.MiddlewareFunc {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ip := r.RemoteAddr
			limiter := rl.GetLimiter(ip)
			if !limiter.Allow() {
				log.Printf("Rate limit exceeded for IP: %s", ip)
				http.Error(w, "Rate limit exceeded", http.StatusTooManyRequests)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

// gzipMiddleware compresses responses if the client supports gzip encoding.
func gzipMiddleware(next http.Handler) http.Handler {
    return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        if strings.Contains(r.Header.Get("Connection"), "Upgrade") && strings.Contains(r.Header.Get("Upgrade"), "websocket") {
            next.ServeHTTP(w, r)
            return
        }
        if !strings.Contains(r.Header.Get("Accept-Encoding"), "gzip") {
            next.ServeHTTP(w, r)
            return
        }
        w.Header().Set("Content-Encoding", "gzip")
        gz, err := gzip.NewWriterLevel(w, gzip.BestSpeed)
        if err != nil {
            log.Printf("Failed to create gzip writer: %v", err)
            http.Error(w, "Internal Server Error", http.StatusInternalServerError)
            return
        }
        defer gz.Close()
        gzw := GzipResponseWriter{Writer: gz, ResponseWriter: w}
        next.ServeHTTP(gzw, r)
    })
}

// rewriteMiddleware demonstrates URL rewriting/redirection.
func rewriteMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/old") {
			newURL := *r.URL
			newURL.Path = strings.Replace(newURL.Path, "/old", "/new", 1)
			http.Redirect(w, r, newURL.String(), http.StatusMovedPermanently)
			log.Printf("Rewriting %s to %s (redirect)", r.URL.Path, newURL.Path)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// reverseProxyHandler proxies requests to a backend server selected by the LoadBalancer.
func reverseProxyHandler(lb *LoadBalancer) http.HandlerFunc {
    return func(w http.ResponseWriter, r *http.Request) {
        target := lb.NextServer()
        url, err := url.Parse(target)
        if err != nil {
            log.Printf("Error parsing proxy target URL %s: %v", target, err)
            http.Error(w, "Bad gateway", http.StatusBadGateway)
            return
        }
        proxy := httputil.NewSingleHostReverseProxy(url)
        proxy.ModifyResponse = func(resp *http.Response) error {
            resp.Header.Del("Content-Encoding")
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
func webSocketHandler(w http.ResponseWriter, r *http.Request) {
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
			return
		}
		log.Printf("Received WebSocket message from %s (type %d): %s", r.RemoteAddr, messageType, string(p))
		if err := conn.WriteMessage(messageType, p); err != nil {
			log.Printf("WebSocket write error to %s: %v", r.RemoteAddr, err)
			return
		}
	}
}

// staticFileHandler serves static files from a directory with in-memory caching.
func staticFileHandler(staticDir string, cache *Cache) http.Handler {
    return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
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
                if k != "Content-Encoding" {
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
                http.Error(w, "File not found", http.StatusNotFound)
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
        // mimeType := http.DetectContentType(body)
        // ext := strings.ToLower(filepath.Ext(fullPath))
        // switch ext {
        // case ".css":
        //     mimeType = "text/css"
        // case ".js":
        //     mimeType = "application/javascript"
        // case ".json":
        //     mimeType = "application/json"
        // case ".svg":
        //     mimeType = "image/svg+xml"
        // case ".woff":
        //     mimeType = "font/woff"
        // case ".woff2":
        //     mimeType = "font/woff2"
        // case ".ttf":
        //     mimeType = "font/ttf"
        // case ".eot":
        //     mimeType = "application/vnd.ms-fontobject"
        // case ".ico":
        //     mimeType = "image/x-icon"
        // }

		// Determine MIME type using the MimeTypeMap first, then fallback to DetectContentType
		mimeType := ""
		ext := strings.ToLower(filepath.Ext(fullPath))
		if mt, ok := MimeTypeMap[ext]; ok {
			mimeType = mt
		} else {
			mimeType = http.DetectContentType(body)
		}
        w.Header().Set("Content-Type", mimeType)
        w.Write(body)
        headersToCache := make(http.Header)
        for k, v := range w.Header() {
            if k != "Content-Encoding" {
                headersToCache[k] = v
            }
        }
        cache.Set(cacheKey, body, headersToCache, mimeType)
        log.Printf("Served %s and cached for future requests", requestedPath)
    })
}

func main() {
	// Load configuration from config.json
	configFile, err := os.ReadFile("config.json")
	if err != nil {
		log.Fatalf("Failed to read config.json: %v", err)
	}
	var config Config
	if err := json.Unmarshal(configFile, &config); err != nil {
		log.Fatalf("Failed to parse config.json: %v", err)
	}

	r := mux.NewRouter()
	rl := NewRateLimiter(rate.Limit(config.RateLimitRPS), config.RateLimitBurst)
	lb := NewLoadBalancer(config.ProxyTargets)
	cache := NewCache(time.Duration(config.CacheTTLSeconds) * time.Second)

	// Proxy handler: Routes requests to backend servers via load balancing.
	r.HandleFunc("/proxy", reverseProxyHandler(lb))

	// WebSocket handler: Provides a bidirectional communication channel.
	r.HandleFunc("/ws", webSocketHandler)

	// Rewritten URL handler: A destination for the /old to /new rewrite.
	r.PathPrefix("/new/").HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "You've reached the rewritten URL: %s", r.URL.Path)
	})

	// Static files handler: Serve everything from root
	r.PathPrefix("/").Handler(staticFileHandler(config.StaticDir, cache))

	// Catch-all route: Serve index.html for non-file, non-API paths (SPA support)
	r.NotFoundHandler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		indexPath := filepath.Join(config.StaticDir, "index.html")
		f, err := os.Open(indexPath)
		if err != nil {
			http.Error(w, "index.html not found", http.StatusInternalServerError)
			return
		}
		defer f.Close()
		body, err := io.ReadAll(f)
		if err != nil {
			http.Error(w, "Error reading index.html", http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Write(body)
	})

	//APPLY MIDDLEWARES
	r.Use(loggingMiddleware)
	r.Use(rateLimitMiddleware(rl))
	r.Use(gzipMiddleware)
	r.Use(rewriteMiddleware)

	server := &http.Server{
		Addr:         ":" + config.Port,
		Handler:      r,
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 10 * time.Second,
	}

	http2.ConfigureServer(server, &http2.Server{})

	certFile := "cert.pem"
	keyFile := "key.pem"
	_, errCert := os.Stat(certFile)
	_, errKey := os.Stat(keyFile)
	if os.IsNotExist(errCert) || os.IsNotExist(errKey) {
		log.Println("TLS certs (cert.pem and key.pem) not found.")
		generateSelfSignedCert()
	}

	log.Printf("Webber Web Server starting on :%s with TLS and HTTP/2...", config.Port)
	if err := server.ListenAndServeTLS(certFile, keyFile); err != nil {
		log.Fatalf("Webber Web Server failed to start: %v", err)
	}
}

// generateSelfSignedCert provides instructions for generating self-signed TLS certificates
// and then exits the program. This is for development/testing purposes.
func generateSelfSignedCert() {
	log.Println("To enable HTTPS, please generate self-signed certificates 'cert.pem' and 'key.pem'.")
	log.Println("You can use OpenSSL with the following command:")
	log.Println("  openssl req -x509 -newkey rsa:4096 -keyout key.pem -out cert.pem -days 365 -nodes")
	log.Println("  (When prompted, for 'Common Name (e.g. server FQDN or YOUR name)', use 'localhost' for local testing.)")
	os.Exit(1)
}
