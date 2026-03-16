package middleware

import (
	"fmt"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/ulule/limiter/v3"
	"github.com/ulule/limiter/v3/drivers/store/memory"
	"go.uber.org/zap"
)

// RateLimiter returns a Gin middleware enforcing a per-IP request rate limit.
// The in-memory store is appropriate for a single-instance deployment; replace
// with a Redis store for a horizontally-scaled cluster.
func RateLimiter(requestsPerMinute int64, logger *zap.Logger) gin.HandlerFunc {
	rate := limiter.Rate{
		Period: 60_000_000_000, // 1 minute in nanoseconds
		Limit:  requestsPerMinute,
	}

	store := memory.NewStore()
	instance := limiter.New(store, rate)

	return func(c *gin.Context) {
		ctx, err := instance.Get(c, c.ClientIP())
		if err != nil {
			logger.Error("rate limiter store error", zap.Error(err))
			c.Next()
			return
		}

		c.Header("X-RateLimit-Limit", formatInt(ctx.Limit))
		c.Header("X-RateLimit-Remaining", formatInt(ctx.Remaining))
		c.Header("X-RateLimit-Reset", formatInt(ctx.Reset))

		if ctx.Reached {
			c.AbortWithStatusJSON(http.StatusTooManyRequests, gin.H{
				"error": "rate limit exceeded",
			})
			return
		}

		c.Next()
	}
}

func formatInt(n int64) string {
	return fmt.Sprintf("%d", n)
}
