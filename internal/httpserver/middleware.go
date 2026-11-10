//lint:file-ignore U1000 Some code in this file is used later

package httpserver

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"math"
	"net"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"
	"uuid"

	"github.com/bootdotdev/learn-web-security/internal/httpx"
	"github.com/bootdotdev/learn-web-security/internal/logging"
	"github.com/bootdotdev/learn-web-security/internal/templates"
)

type middleware func(http.Handler) http.Handler

func applyMiddleware(handler http.Handler, middlewareChain ...middleware) http.Handler {
	for _, currentMiddleware := range slices.Backward(middlewareChain) {
		handler = currentMiddleware(handler)
	}
	return handler
}

type requestIDContextKey struct{}

func requestIDMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(
		responseWriter http.ResponseWriter,
		request *http.Request,
	) {
		requestID := uuid.NewV4()

		responseWriter.Header().Set(
			"X-Request-ID",
			requestID.String(),
		)

		ctx := context.WithValue(
			request.Context(),
			requestIDContextKey{},
			requestID,
		)

		next.ServeHTTP(responseWriter, request.WithContext(ctx))
	})
}

func publicProductsCORS(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		next.ServeHTTP(w, r)
	})
}

func handleProductsOptions(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Allow-Methods", "GET")
	w.WriteHeader(http.StatusNoContent)
}

/*func permissiveCORS(next http.Handler) http.Handler {
	return http.HandlerFunc(func(responseWriter http.ResponseWriter, request *http.Request) {
		if origin := request.Header.Get("Origin"); origin != "" {
			responseWriter.Header().Set("Access-Control-Allow-Origin", origin)
			responseWriter.Header().Set("Access-Control-Allow-Credentials", "true")
			responseWriter.Header().Set("Vary", "Origin")
		}
		if request.Method == http.MethodOptions {
			responseWriter.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, PATCH, DELETE, OPTIONS")
			responseWriter.Header().Set("Access-Control-Allow-Headers", request.Header.Get("Access-Control-Request-Headers"))
			responseWriter.WriteHeader(http.StatusNoContent)
			return
		}
		next.ServeHTTP(responseWriter, request)
	})
}*/

func validateRequestSource(appOrigin string, renderer *templates.Renderer) middleware {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(responseWriter http.ResponseWriter, request *http.Request) {
			// Non-POST requests are allowed.
			if request.Method != http.MethodPost {
				next.ServeHTTP(responseWriter, request)
				return
			}

			trusted := false

			originValues := request.Header.Values("Origin")

			if len(originValues) > 0 {
				// If Origin exists, it must match exactly.
				trusted = len(originValues) == 1 && originValues[0] == appOrigin
			} else {
				// Only fall back to Referer when Origin is absent.
				refererValues := request.Header.Values("Referer")

				if len(refererValues) == 1 {
					refererURL, err := url.Parse(refererValues[0])

					if err == nil &&
						refererURL.IsAbs() &&
						refererURL.Host != "" &&
						refererURL.User == nil &&
						(refererURL.Scheme == "http" || refererURL.Scheme == "https") {

						refererOrigin := refererURL.Scheme + "://" + refererURL.Host
						trusted = refererOrigin == appOrigin
					}
				}
			}

			if !trusted {
				if err := httpx.RespondWithErrorPage(
					responseWriter,
					renderer,
					http.StatusForbidden,
					"Forbidden",
					"Your request source could not be verified.",
				); err != nil {
					http.Error(
						responseWriter,
						http.StatusText(http.StatusInternalServerError),
						http.StatusInternalServerError,
					)
				}
				return
			}

			next.ServeHTTP(responseWriter, request)
		})
	}
}

func cspNonce(next http.Handler) http.Handler {
	return http.HandlerFunc(func(responseWriter http.ResponseWriter, request *http.Request) {
		nonceBytes := make([]byte, 16)
		if _, err := rand.Read(nonceBytes); err != nil {
			http.Error(responseWriter, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
			return
		}
		nonce := base64.StdEncoding.EncodeToString(nonceBytes)
		request = request.WithContext(httpx.WithCSPNonce(request.Context(), nonce))
		next.ServeHTTP(responseWriter, request)
	})
}

/*func contentSecurityPolicy(next http.Handler) http.Handler {
	return http.HandlerFunc(func(responseWriter http.ResponseWriter, request *http.Request) {
		nonce := httpx.CSPNonce(request.Context())

		responseWriter.Header().Set(
			"Content-Security-Policy",
			"default-src 'self'; script-src 'self' 'nonce-"+nonce+"'; style-src 'self'; img-src 'self' data:; frame-src 'self'; object-src 'none'; base-uri 'self'; form-action 'self'; frame-ancestors 'self'",
		)

		responseWriter.Header().Set(
			"X-Frame-Options",
			"SAMEORIGIN",
		)

		responseWriter.Header().Set(
			"Referrer-Policy",
			"strict-origin-when-cross-origin",
		)

		next.ServeHTTP(responseWriter, request)
	})
}*/

func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		nonce := httpx.CSPNonce(r.Context())

		// Content Security Policy
		w.Header().Set(
			"Content-Security-Policy",
			"default-src 'self'; script-src 'self' 'nonce-"+nonce+"'; style-src 'self'; img-src 'self' data:; frame-src 'self'; object-src 'none'; base-uri 'self'; form-action 'self'; frame-ancestors 'self'",
		)

		// Existing security headers
		w.Header().Set("Referrer-Policy", "strict-origin-when-cross-origin")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "SAMEORIGIN")

		// Additional security headers
		w.Header().Set("Cross-Origin-Opener-Policy", "same-origin")
		w.Header().Set("Cross-Origin-Resource-Policy", "same-origin")
		w.Header().Set("Origin-Agent-Cluster", "?1")
		w.Header().Set("X-DNS-Prefetch-Control", "off")
		w.Header().Set("X-Download-Options", "noopen")
		w.Header().Set("X-Permitted-Cross-Domain-Policies", "none")
		w.Header().Set("X-XSS-Protection", "0")

		next.ServeHTTP(w, r)
	})
}

func recoverPanics(logger *logging.Logger, renderer *templates.Renderer) middleware {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(responseWriter http.ResponseWriter, request *http.Request) {
			defer func() {
				if recovered := recover(); recovered != nil {
					_ = logger.Event("unhandled_error", map[string]any{
						"method":  request.Method,
						"path":    request.URL.Path,
						"message": fmt.Sprint(recovered),
					})
					if err := httpx.RespondWithErrorPage(responseWriter, renderer, http.StatusInternalServerError, "Unhandled Error", fmt.Sprint(recovered)); err != nil {
						http.Error(responseWriter, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
					}
				}
			}()
			next.ServeHTTP(responseWriter, request)
		})
	}
}

func LoadShedder(maxConcurrent int, retryAfterSeconds int) func(http.Handler) http.Handler {
	// Validate configuration before allocating channel
	if maxConcurrent <= 0 {
		panic("max concurrent requests must be positive")
	}

	if retryAfterSeconds <= 0 {
		panic("retry after seconds must be positive")
	}

	// Shared buffered channel to track in-flight requests
	inFlight := make(chan struct{}, maxConcurrent)

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(responseWriter http.ResponseWriter, request *http.Request) {

			// Set limit header on every response
			responseWriter.Header().Set(
				"X-In-Flight-Limit",
				fmt.Sprintf("%d", maxConcurrent),
			)

			// Try to acquire capacity without blocking
			select {
			case inFlight <- struct{}{}:

				// Release capacity even if handler panics
				defer func() {
					<-inFlight
				}()

				// Process request
				next.ServeHTTP(responseWriter, request)

			default:
				// Server is at capacity
				responseWriter.Header().Set(
					"Retry-After",
					fmt.Sprintf("%d", retryAfterSeconds),
				)

				httpx.RespondWithJSON(
					responseWriter,
					http.StatusServiceUnavailable,
					map[string]string{
						"error": "Service is at capacity",
					},
				)
			}
		})
	}
}

func SearchThrottle(renderer *templates.Renderer) func(http.Handler) http.Handler {
	return fixedWindowRateLimiter(rateLimitOptions{
		window:  time.Second,
		maximum: 5,
		key: func(_ *http.Request) string {
			return "search"
		},
		onLimit: func(w http.ResponseWriter, _ *http.Request, _ rateLimitState) {
			if err := httpx.RespondWithErrorPage(
				w,
				renderer,
				http.StatusTooManyRequests,
				"Search Is Busy",
				"Try again shortly.",
			); err != nil {
				http.Error(
					w,
					http.StatusText(http.StatusInternalServerError),
					http.StatusInternalServerError,
				)
			}
		},
	})
}

type rateLimitCounter struct {
	count   int
	resetAt time.Time
}

type rateLimitOptions struct {
	window  time.Duration
	maximum int
	key     func(*http.Request) string
	onLimit func(http.ResponseWriter, *http.Request, rateLimitState)
	now     func() time.Time
}

type rateLimitState struct {
	limit             int
	remaining         int
	resetAt           time.Time
	retryAfterSeconds int
}

type fixedWindowLimiter struct {
	options       rateLimitOptions
	counters      map[string]rateLimitCounter
	countersMutex sync.Mutex
	nextSweepAt   time.Time
}

func newFixedWindowLimiter(options rateLimitOptions) *fixedWindowLimiter {
	validateRateLimitOptions(options)
	if options.now == nil {
		options.now = time.Now
	}
	if options.key == nil {
		options.key = clientIPKey
	}
	return &fixedWindowLimiter{
		options:     options,
		counters:    make(map[string]rateLimitCounter),
		nextSweepAt: options.now().Add(options.window),
	}
}

func validateRateLimitOptions(options rateLimitOptions) {
	if options.window <= 0 {
		panic("rate-limit window must be positive")
	}
	if options.maximum <= 0 {
		panic("rate-limit maximum must be positive")
	}
}

func (limiter *fixedWindowLimiter) consume(request *http.Request) (rateLimitState, bool) {
	now := limiter.options.now()
	key := limiter.options.key(request)

	limiter.countersMutex.Lock()
	defer limiter.countersMutex.Unlock()
	limiter.sweepExpiredCounters(now)

	counter, exists := limiter.counters[key]
	if !exists || !now.Before(counter.resetAt) {
		counter = rateLimitCounter{resetAt: now.Add(limiter.options.window)}
	}
	retryAfterSeconds := max(1, int(math.Ceil(counter.resetAt.Sub(now).Seconds())))
	if counter.count >= limiter.options.maximum {
		return rateLimitState{
			limit:             limiter.options.maximum,
			remaining:         0,
			resetAt:           counter.resetAt,
			retryAfterSeconds: retryAfterSeconds,
		}, true
	}

	counter.count++
	limiter.counters[key] = counter
	return rateLimitState{
		limit:             limiter.options.maximum,
		remaining:         limiter.options.maximum - counter.count,
		resetAt:           counter.resetAt,
		retryAfterSeconds: retryAfterSeconds,
	}, false
}

func (limiter *fixedWindowLimiter) sweepExpiredCounters(now time.Time) {
	if now.Before(limiter.nextSweepAt) {
		return
	}
	for counterKey, counter := range limiter.counters {
		if !now.Before(counter.resetAt) {
			delete(limiter.counters, counterKey)
		}
	}
	limiter.nextSweepAt = now.Add(limiter.options.window)
}

func (limiter *fixedWindowLimiter) reject(responseWriter http.ResponseWriter, request *http.Request, state rateLimitState) {
	setRateLimitHeaders(responseWriter, state)
	responseWriter.Header().Set("Retry-After", strconv.Itoa(state.retryAfterSeconds))
	if limiter.options.onLimit != nil {
		limiter.options.onLimit(responseWriter, request, state)
		return
	}
	httpx.RespondWithJSON(responseWriter, http.StatusTooManyRequests, map[string]string{"error": "Too many requests"})
}

func fixedWindowRateLimiter(options rateLimitOptions) middleware {
	limiter := newFixedWindowLimiter(options)

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			state, limited := limiter.consume(r)

			if limited {
				limiter.reject(w, r, state)
				return
			}

			setRateLimitHeaders(w, state)
			next.ServeHTTP(w, r)
		})
	}
}

func setRateLimitHeaders(responseWriter http.ResponseWriter, state rateLimitState) {
	responseWriter.Header().Set("RateLimit-Limit", strconv.Itoa(state.limit))
	responseWriter.Header().Set("RateLimit-Remaining", strconv.Itoa(state.remaining))
	responseWriter.Header().Set("RateLimit-Reset", strconv.FormatInt(state.resetAt.Unix()+boolToInt64(state.resetAt.Nanosecond() > 0), 10))
}

func clientIPKey(request *http.Request) string {
	host, _, err := net.SplitHostPort(request.RemoteAddr)
	if err == nil && host != "" {
		return host
	}
	if request.RemoteAddr != "" {
		return request.RemoteAddr
	}
	return "unknown"
}

func clientIPKeyWithTrustedProxies(trustedProxyHops int) func(*http.Request) string {
	return func(request *http.Request) string {
		if trustedProxyHops > 0 {
			forwardedAddresses := strings.Split(request.Header.Get("X-Forwarded-For"), ",")
			selectedIndex := len(forwardedAddresses) - trustedProxyHops
			if selectedIndex >= 0 && selectedIndex < len(forwardedAddresses) {
				if selectedAddress := strings.TrimSpace(forwardedAddresses[selectedIndex]); selectedAddress != "" {
					return selectedAddress
				}
			}
		}
		return clientIPKey(request)
	}
}

func boolToInt64(value bool) int64 {
	if value {
		return 1
	}
	return 0
}

func middlewareNoSniff(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")

		next.ServeHTTP(w, r)
	})
}

func allowCrossOriginResourcePolicy(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cross-Origin-Resource-Policy", "cross-origin")
		next.ServeHTTP(w, r)
	})
}
