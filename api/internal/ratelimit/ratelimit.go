package ratelimit

import (
	"context"
	"database/sql"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"api/internal/shared"

	"errors"

	"github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"
	"github.com/redis/go-redis/v9"
	"go.uber.org/zap"
	"golang.org/x/time/rate"
)

const (
	// Redis key for storing chargeable status
	chargeableKeyPrefix = "apikey:chargeable:"
	// TTL for chargeable status in Redis
	chargeableTTL = 24 * time.Hour

	requestsPerSecond = 0.2
	// Burst limit: allow this many requests in a burst (can be adjusted based on load)
	burstSize = 1
	// Window size for rate limiting (sliding window)
	rateLimitWindow = 5 * time.Second

	// Redis key prefix for rate limiting
	rateLimitKeyPrefix = "ratelimit:"
)

// RateLimitResult represents the result of a rate limit check
type RateLimitResult struct {
	Limit      int
	Remaining  int
	ResetTime  time.Time
	ResetAfter time.Duration
}

// RedisRateLimiter implements a Redis-based rate limiter
type RedisRateLimiter struct {
	redisClient *redis.Client
	rate        rate.Limit
	burst       int
	expiresIn   time.Duration
}

// Allow checks if a request is allowed based on the rate limit
func (r *RedisRateLimiter) Allow(ctx context.Context, identifier string) (bool, error) {
	now := time.Now()
	key := rateLimitKeyPrefix + identifier
	oldestAllowedTime := now.Add(-r.expiresIn).Unix()
	oldestTimeStr := strconv.FormatInt(oldestAllowedTime, 10)

	// Setup pipeline to perform all Redis operations atomically
	pipe := r.redisClient.Pipeline()
	countCmd := pipe.ZCount(ctx, key, oldestTimeStr, "+inf")
	pipe.ZAdd(ctx, key, redis.Z{Score: float64(now.Unix()), Member: now.UnixNano()})
	pipe.ZRemRangeByScore(ctx, key, "-inf", oldestTimeStr)
	pipe.Expire(ctx, key, r.expiresIn)

	// Execute pipeline
	_, err := pipe.Exec(ctx)
	if err != nil {
		return false, err
	}

	// Get count of requests in the time window
	count, err := countCmd.Result()
	if err != nil {
		return false, err
	}

	// Allow if count is less than burst limit
	return count < int64(r.burst), nil
}

// GetRateLimitResult gets the current rate limit status
func (r *RedisRateLimiter) GetRateLimitResult(ctx context.Context, identifier string) (RateLimitResult, error) {
	now := time.Now()
	key := rateLimitKeyPrefix + identifier
	oldestAllowedTime := now.Add(-r.expiresIn).Unix()
	oldestTimeStr := strconv.FormatInt(oldestAllowedTime, 10)

	// Setup pipeline to perform all Redis operations atomically
	pipe := r.redisClient.Pipeline()
	countCmd := pipe.ZCount(ctx, key, oldestTimeStr, "+inf")
	pipe.ZRemRangeByScore(ctx, key, "-inf", oldestTimeStr)
	pipe.Expire(ctx, key, r.expiresIn)

	// Execute pipeline
	_, err := pipe.Exec(ctx)
	if err != nil {
		return RateLimitResult{}, err
	}

	// Get count of requests in the time window
	count, err := countCmd.Result()
	if err != nil {
		return RateLimitResult{}, err
	}

	// Calculate remaining requests
	remaining := max(int64(r.burst)-count, 0)

	resetTime := now.Add(r.expiresIn)

	return RateLimitResult{
		Limit:      r.burst,
		Remaining:  int(remaining),
		ResetTime:  resetTime,
		ResetAfter: r.expiresIn,
	}, nil
}

// IsApiKeyChargeable checks if an API key is chargeable, using Redis as a cache
func IsApiKeyChargeable(ctx context.Context, redisClient *redis.Client, readDb *sql.DB, apiKey string, logger *zap.SugaredLogger) (bool, error) {
	if apiKey == "" {
		return false, fmt.Errorf("empty API key")
	}

	chargeableKey := fmt.Sprintf("%s%s", chargeableKeyPrefix, apiKey)

	// Try to get from cache first
	val, err := redisClient.Get(ctx, chargeableKey).Result()
	if err == nil {
		return val == "1", nil
	}

	// Handle Redis errors other than key not found
	if err != redis.Nil {
		logger.Warnw("Redis error when checking chargeable status", "error", err, "apiKey", apiKey)
	}

	// Query the database
	queryCtx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()

	var chargeable bool
	err = readDb.QueryRowContext(queryCtx, "SELECT user.chargeable FROM api_key JOIN user ON api_key.user_id = user.id WHERE api_key.id = ?", apiKey).Scan(&chargeable)

	// Handle database errors
	if err == sql.ErrNoRows {
		// Cache the non-chargeable status
		if setErr := redisClient.Set(ctx, chargeableKey, "0", chargeableTTL).Err(); setErr != nil && logger != nil {
			logger.Warnw("Failed to cache non-chargeable status", "error", setErr, "apiKey", apiKey)
		}
		return false, nil
	}

	if err != nil {
		return false, err
	}

	// Cache the result
	cacheValue := "0"
	if chargeable {
		cacheValue = "1"
	}

	if setErr := redisClient.Set(ctx, chargeableKey, cacheValue, chargeableTTL).Err(); setErr != nil && logger != nil {
		logger.Warnw("Failed to cache chargeable status", "error", setErr, "apiKey", apiKey)
	}

	return chargeable, nil
}

// ExtractApiKey extracts the API key from the request
func ExtractApiKey(c echo.Context) (string, error) {
	// Check Authorization header
	auth := c.Request().Header.Get("Authorization")
	if auth != "" {
		parts := strings.Split(auth, " ")
		if len(parts) == 2 && strings.ToLower(parts[0]) == "bearer" {
			return parts[1], nil
		}
	}

	// Check query parameter
	apiKey := c.QueryParam("api_key")
	if apiKey != "" {
		return apiKey, nil
	}

	return "", fmt.Errorf("no API key found")
}

// CustomRateLimiterStore adapts our Redis rate limiter to Echo's middleware interface
type CustomRateLimiterStore struct {
	limiter *RedisRateLimiter
}

// Allow implements the middleware.RateLimiterStore interface
// Note: This method uses a background context since Echo's middleware doesn't provide one
func (s *CustomRateLimiterStore) Allow(identifier string) (bool, error) {
	return s.limiter.Allow(context.Background(), identifier)
}

// ConfigureRateLimiter sets up the Echo rate limiter middleware
func ConfigureRateLimiter(readDb *sql.DB, redisClient *redis.Client) echo.MiddlewareFunc {
	limiter := &RedisRateLimiter{
		redisClient: redisClient,
		rate:        rate.Limit(requestsPerSecond),
		burst:       burstSize,
		expiresIn:   rateLimitWindow,
	}

	store := &CustomRateLimiterStore{
		limiter: limiter,
	}

	config := middleware.RateLimiterConfig{
		Skipper: func(c echo.Context) bool {
			cc, ok := c.(*shared.Context)
			if !ok {
				return true // Skip if not our custom context
			}

			apiKey, err := ExtractApiKey(c)
			if err != nil {
				cc.Log.Warnw("No API key found for rate limiting", "path", cc.Request().URL.Path, "error", err.Error())
				return true
			}

			chargeable, err := IsApiKeyChargeable(c.Request().Context(), redisClient, readDb, apiKey, cc.Log)
			if err != nil {
				if err != redis.Nil {
					cc.Log.Warnw("Redis error when checking if API key is chargeable", "error", err.Error(), "apiKey", apiKey)
				}
				cc.Log.Errorw("Failed to check if API key is chargeable", "error", err.Error(), "apiKey", apiKey)
				return true
			}

			// Only apply rate limiting to chargeable API keys
			return !chargeable
		},
		IdentifierExtractor: func(c echo.Context) (string, error) {
			apiKey, err := ExtractApiKey(c)
			if err != nil {
				return "", err
			}
			return fmt.Sprintf("apikey:%s", apiKey), nil
		},
		Store: store,
		ErrorHandler: func(c echo.Context, err error) error {
			cc, ok := c.(*shared.Context)
			if !ok {
				return echo.NewHTTPError(http.StatusInternalServerError, "Internal server error")
			}
			cc.Log.Errorw("Rate limit identifier extraction error", "error", err.Error())
			return c.JSON(http.StatusInternalServerError, shared.OpenAIError{
				Message: "Internal server error",
				Object:  "error",
				Type:    "internal_error",
				Code:    500,
			})
		},
		DenyHandler: func(c echo.Context, identifier string, err error) error {
			// Set default rate limit headers
			defaultHeaders := func(c echo.Context) {
				c.Response().Header().Set("X-RateLimit-Limit", strconv.Itoa(burstSize))
				c.Response().Header().Set("X-RateLimit-Remaining", "0")
				c.Response().Header().Set("X-RateLimit-Reset", strconv.FormatInt(time.Now().Add(rateLimitWindow).Unix(), 10))
				c.Response().Header().Set("Retry-After", strconv.Itoa(int(rateLimitWindow.Seconds())))
			}

			cc, ok := c.(*shared.Context)
			if !ok {
				defaultHeaders(c)
				return echo.NewHTTPError(http.StatusTooManyRequests, "Rate limit exceeded")
			}

			shortIdentifier := strings.TrimPrefix(identifier, "apikey:")

			cc.Log.Infow("Rate limit exceeded",
				"identifier", shortIdentifier,
				"path", c.Request().URL.Path,
				"method", c.Request().Method,
			)

			ctx, cancel := context.WithTimeout(c.Request().Context(), 500*time.Millisecond)
			defer cancel()

			result, resultErr := limiter.GetRateLimitResult(ctx, identifier)
			if resultErr != nil {
				if errors.Is(resultErr, context.Canceled) {
					cc.Log.Infow("Client likely canceled request during rate limit check",
						"apiKey", shortIdentifier,
					)
				} else if errors.Is(resultErr, context.DeadlineExceeded) {
					cc.Log.Infow("Rate limit request timed out",
						"apiKey", shortIdentifier,
					)
				} else {
					cc.Log.Errorw("Failed to get rate limit result",
						"error", resultErr.Error(),
						"apiKey", shortIdentifier,
					)
				}

				defaultHeaders(c)
			} else {
				// Set headers with actual rate limit information
				c.Response().Header().Set("X-RateLimit-Limit", strconv.Itoa(result.Limit))
				c.Response().Header().Set("X-RateLimit-Remaining", strconv.Itoa(result.Remaining))
				c.Response().Header().Set("X-RateLimit-Reset", strconv.FormatInt(result.ResetTime.Unix(), 10))
				c.Response().Header().Set("Retry-After", strconv.Itoa(int(result.ResetAfter.Seconds())))
			}

			message := "Rate limit exceeded. Please slow down your requests."
			if err != nil {
				message = fmt.Sprintf("%s Error: %s", message, err.Error())
			}

			return c.JSON(http.StatusTooManyRequests, shared.OpenAIError{
				Message: message,
				Object:  "error",
				Type:    "rate_limit_exceeded",
				Code:    http.StatusTooManyRequests,
			})
		},
	}

	return middleware.RateLimiterWithConfig(config)
}
