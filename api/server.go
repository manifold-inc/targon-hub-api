package main

import (
	"database/sql"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/aidarkhanov/nanoid"
	_ "github.com/go-sql-driver/mysql"
	"github.com/google/uuid"
	"github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"
	"github.com/redis/go-redis/v9"
	"go.uber.org/zap"
)

var (
	HOTKEY           string
	PUBLIC_KEY       string
	PRIVATE_KEY      string
	INSTANCE_UUID    string
	DEBUG            bool
	FALLBACK_API_KEY string

	client *redis.Client
)

var (
	Reset  = "\033[0m"
	Red    = "\033[31m"
	Green  = "\033[32m"
	Yellow = "\033[33m"
	Blue   = "\033[34m"
	Purple = "\033[35m"
	Cyan   = "\033[36m"
	Gray   = "\033[37m"
	White  = "\033[97m"
)

type Context struct {
	echo.Context
	log   *zap.SugaredLogger
	reqid string
}

func main() {
	HOTKEY = safeEnv("HOTKEY")
	PUBLIC_KEY = safeEnv("PUBLIC_KEY")
	PRIVATE_KEY = safeEnv("PRIVATE_KEY")
	FALLBACK_API_KEY = safeEnv("FALLBACK_API_KEY")
	DSN := safeEnv("DSN")
	REDIS_HOST := getEnv("REDIS_HOST", "cache")
	REDIS_PORT := getEnv("REDIS_PORT", "6379")
	INSTANCE_UUID = uuid.New().String()
	debug, present := os.LookupEnv("DEBUG")

	if !present {
		DEBUG = false
	} else {
		DEBUG, _ = strconv.ParseBool(debug)
	}

	var err error
	logger, err := zap.NewProduction()
	if err != nil {
		panic("Failed to get logger")
	}
	sugar := logger.Sugar()

	e := echo.New()
	e.Use(middleware.CORS())
	e.Use(func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			reqId, _ := nanoid.Generate("0123456789abcdefghijklmnopqrstuvwxyz", 28)
			logger := sugar.With(
				"request_id", "req_"+reqId,
			)

			cc := &Context{c, logger, reqId}
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
	db, _ := sql.Open("mysql", DSN)
	err = db.Ping()
	if err != nil {
		sugar.Error(err.Error())
	}
	defer db.Close()

	client = redis.NewClient(&redis.Options{
		Addr:     fmt.Sprintf("%s:%s", REDIS_HOST, REDIS_PORT),
		Password: "",
		DB:       0,
	})
	defer client.Close()

	e.POST("/v1/chat/completions", func(c echo.Context) error {
		cc := c.(*Context)
		defer func() {
			_ = cc.log.Sync()
		}()
		request, preprocessError := preprocessOpenaiRequest(cc, db, ENDPOINTS.CHAT)
		if preprocessError != nil {
			return cc.String(preprocessError.StatusCode, preprocessError.Error())
		}

		res, err := queryMiners(cc, request)
		if err != nil {
			cc.log.Warnw("Failed request, most likely un-recoverable. Not sending to fallback", "error", err.Error(), "final", true)
			return c.JSON(500, OpenAIError{
				Message: err.Error(),
				Object:  "error",
				Type:    "InternalServerError",
				Code:    500,
			})
		}
		go saveRequest(db, res, request, cc.log)
		if res.Success {
			return c.String(200, "")
		}

		cc.log.Warnw("failed request, sending to fallback", "uid", res.Miner.Uid, "hotkey", res.Miner.Hotkey, "coldkey", res.Miner.Coldkey)
		qerr := QueryFallback(cc, db, request)
		if qerr != nil {
			cc.log.Warnw("Failed fallback", "error", qerr.Error(), "final", true)
			return c.JSON(503, OpenAIError{
				Message: qerr.Error(),
				Object:  "error",
				Type:    "APITimeoutError",
				Code:    qerr.StatusCode,
			})
		}

		return c.String(200, "")
	})

	e.POST("/v1/completions", func(c echo.Context) error {
		cc := c.(*Context)
		defer func() {
			_ = cc.log.Sync()
		}()
		request, preprocessError := preprocessOpenaiRequest(cc, db, ENDPOINTS.COMPLETION)
		if preprocessError != nil {
			return cc.String(preprocessError.StatusCode, preprocessError.Error())
		}

		res, err := queryMiners(cc, request)
		if err != nil {
			cc.log.Warnw("Failed request, most likely un-recoverable. Not sending to fallback", "error", err.Error(), "final", true)
			return c.JSON(500, OpenAIError{
				Message: err.Error(),
				Object:  "error",
				Type:    "InternalServerError",
				Code:    500,
			})
		}
		go saveRequest(db, res, request, cc.log)
		if res.Success {
			return c.String(200, "")
		}

		cc.log.Warnw("failed request, sending to fallback", "uid", res.Miner.Uid, "hotkey", res.Miner.Hotkey, "coldkey", res.Miner.Coldkey)
		qerr := QueryFallback(cc, db, request)
		if qerr != nil {
			cc.log.Warnw("Failed fallback", "error", qerr.Error(), "final", true)
			return c.JSON(503, OpenAIError{
				Message: qerr.Error(),
				Object:  "error",
				Type:    "APITimeoutError",
				Code:    qerr.StatusCode,
			})
		}

		return c.String(200, "")
	})

	e.POST("/v1/images/generations", func(c echo.Context) error {
		cc := c.(*Context)
		defer func() {
			_ = cc.log.Sync()
		}()
		request, preprocessError := preprocessOpenaiRequest(cc, db, ENDPOINTS.IMAGE)
		if preprocessError != nil {
			return cc.String(preprocessError.StatusCode, preprocessError.Error())
		}
		res, err := queryMiners(cc, request)

		go saveRequest(db, res, request, cc.log)

		if err != nil {
			cc.log.Warnw("Failed request, sending to fallback server", "error", err.Error())
			return c.String(500, err.Error())
		}

		if !res.Success {
			cc.log.Warnf("Miner %d: %s %s\n Failed request\n", res.Miner.Uid, res.Miner.Hotkey, res.Miner.Coldkey)
			return c.String(500, fmt.Sprintf("Miner UID %d Failed Request. Try Again.", res.Miner.Uid))
		}

		// Send the image response - OpenAI image object
		return c.JSON(200, map[string]interface{}{
			"b64_json": res.Data.Image,
		})
	})

	e.GET("/v1/models", func(c echo.Context) error {
		cc := c.(*Context)
		defer cc.log.Sync()

		rows, err := db.Query(`
			SELECT name, DATE_FORMAT(created_at, '%Y-%m-%d %H:%i:%s') as created_at 
			FROM model WHERE enabled = 1
		`)
		if err != nil {
			cc.log.Error("Failed to get models: " + err.Error())
			return c.String(500, "Failed to get models")
		}
		defer rows.Close()

		var models []Model
		for rows.Next() {
			var model Model
			var createdAtStr string
			if err := rows.Scan(&model.ID, &createdAtStr); err != nil {
				cc.log.Error("Failed to scan model row: " + err.Error())
				return c.String(500, "Failed to get models")
			}

			createdAt, err := time.Parse("2006-01-02 15:04:05", createdAtStr)
			if err != nil {
				cc.log.Error("Failed to parse created_at: " + err.Error())
				return c.String(500, "Failed to get models")
			}

			model.Object = "model"
			model.Created = createdAt.Unix()
			model.OwnedBy = strings.Split(model.ID, "/")[0]

			models = append(models, model)
		}

		if err = rows.Err(); err != nil {
			cc.log.Error("Error iterating model rows: " + err.Error())
			return c.String(500, "Failed to get models")
		}

		return c.JSON(200, ModelList{
			Object: "list",
			Data:   models,
		})
	})

	e.Logger.Fatal(e.Start(":80"))
}
