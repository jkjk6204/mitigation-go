package main

import (
	"fmt"
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/yourusername/ratelimit" // Replace with the actual import path
)

// Define rate limiting parameters.
const (
	rateLimitInterval = time.Second // Rate limiting interval
	rateLimitCapacity = 10          // Maximum requests allowed per second per IP
)

var (
	// Create a token bucket for rate limiting.
	rateLimiter = ratelimit.NewBucket(rateLimitInterval, rateLimitCapacity)

	// IP Whitelist: Add trusted IP addresses here.
	ipWhitelist = []string{"127.0.0.1", "192.168.1.1"}

	// IP Blacklist: Add known malicious IP addresses here.
	ipBlacklist = []string{"10.0.0.1", "10.0.0.2"}

	// Mutex for concurrent access to IP blacklist.
	ipMutex sync.Mutex
)

func main() {
	// Start an HTTP server that enforces rate limiting and IP filtering.
	http.HandleFunc("/", rateLimitMiddleware(IPFilterMiddleware(handleRequest)))
	http.ListenAndServe(":8080", nil)
}

func handleRequest(w http.ResponseWriter, r *http.Request) {
	fmt.Fprintf(w, "Hello, world!\n")
}

// IPFilterMiddleware checks if the client's IP is in the whitelist or blacklist.
// If the IP is in the blacklist, it returns a 403 Forbidden response.
// If the IP is not in the whitelist, it passes the request to the next middleware.
func IPFilterMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		clientIP := getClientIP(r)
		ipMutex.Lock()
		defer ipMutex.Unlock()

		// Check if the IP is in the blacklist.
		for _, bannedIP := range ipBlacklist {
			if clientIP == bannedIP {
				http.Error(w, "Forbidden", http.StatusForbidden)
				return
			}
		}

		// Check if the IP is in the whitelist.
		for _, allowedIP := range ipWhitelist {
			if clientIP == allowedIP {
				next.ServeHTTP(w, r)
				return
			}
		}

		// If the IP is not in either list, allow the request.
		next.ServeHTTP(w, r)
	})
}

// rateLimitMiddleware enforces rate limiting for incoming requests.
func rateLimitMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Limit requests based on the client's IP address.
		clientIP := getClientIP(r)
		waitTime := rateLimiter.Take(1)

		// Check if the request exceeded the rate limit.
		if waitTime > 0 {
			http.Error(w, fmt.Sprintf("Rate limit exceeded. Try again in %s", waitTime), http.StatusTooManyRequests)
			return
		}

		// Continue processing the request.
		next.ServeHTTP(w, r)
	})
}

// getClientIP extracts the client's IP address from the request.
func getClientIP(r *http.Request) string {
	ip, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return ip
}
