package main

import (
	"api/internal/config"
	"api/internal/ratelimit"
	"api/internal/routes"
	"api/internal/shared"

	"github.com/aidarkhanov/nanoid"
	"github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"
	"go.uber.org/zap"
)

func main() {
	logger, err := zap.NewProduction()
	if err != nil {
		panic("Failed to get logger")
	}
	sugar := logger.Sugar()

	cfg, errs := config.InitConfig()
	if errs != nil {
		for _, err := range errs {
			sugar.Errorln(err)
		}
		panic("Failed to init config")
	}
	defer cfg.Shutdown()

	e := echo.New()
	e.Use(middleware.CORS())
	e.Use(func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			reqId, _ := nanoid.Generate("0123456789abcdefghijklmnopqrstuvwxyz", 28)
			logger := sugar.With(
				"request_id", "req_"+reqId,
			)

			cc := &shared.Context{Context: c, Log: logger, Reqid: reqId, Cfg: cfg}
			return next(cc)
		}
	})
	e.Use(middleware.RecoverWithConfig(middleware.RecoverConfig{
		StackSize: 1 << 10, // 1 KB
		LogErrorFunc: func(c echo.Context, err error, stack []byte) error {
			defer func() {
				_ = sugar.Sync()
			}()
			sugar.Errorw("Api Panic", "error", err.Error())
			return c.String(500, "Internal Server Error")
		},
	}))

	// Create a group for rate-limited endpoints
	rateLimitedGroup := e.Group("")

	// Apply cancellation pattern blocker middleware
	rateLimitedGroup.Use(ratelimit.CancellationPatternBlocker(cfg.RedisClient, cfg.ReadSqlClient))

	// Apply rate limiting to endpoints
	rateLimitedGroup.Use(ratelimit.ConfigureRateLimiter(cfg.ReadSqlClient, cfg.RedisClient))

	// Apply rate limiting to chat and completions endpoints
	rateLimitedGroup.POST("/v1/chat/completions", routes.ChatRequest)
	rateLimitedGroup.POST("/v1/completions", routes.CompletionRequest)

	// Non-rate-limited endpoints
	e.GET("/v1/models", routes.Models)

	e.Logger.Fatal(e.Start(":80"))
}
