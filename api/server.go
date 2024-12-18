package main

import (
	"database/sql"
	"fmt"
	"os"
	"strconv"

	"github.com/aidarkhanov/nanoid"
	_ "github.com/go-sql-driver/mysql"
	"github.com/google/uuid"
	"github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"
	"github.com/redis/go-redis/v9"
	"go.uber.org/zap"
)

var (
	HOTKEY        string
	PUBLIC_KEY    string
	PRIVATE_KEY   string
	INSTANCE_UUID string
	DEBUG         bool

	client *redis.Client
)

var Reset = "\033[0m"
var Red = "\033[31m"
var Green = "\033[32m"
var Yellow = "\033[33m"
var Blue = "\033[34m"
var Purple = "\033[35m"
var Cyan = "\033[36m"
var Gray = "\033[37m"
var White = "\033[97m"

type Context struct {
	echo.Context
	log   *zap.SugaredLogger
	reqid string
}

func main() {
	HOTKEY = safeEnv("HOTKEY")
	PUBLIC_KEY = safeEnv("PUBLIC_KEY")
	PRIVATE_KEY = safeEnv("PRIVATE_KEY")
	DSN := safeEnv("DSN")
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
			reqId, _ := nanoid.Generate("0123456789abcdefghijklmnopqrstuvwxyz", 12)
			logger := sugar.With(
				"request_id", reqId,
			)

			cc := &Context{c, logger, reqId}
			return next(cc)
		}
	})
	e.Use(middleware.RecoverWithConfig(middleware.RecoverConfig{
		StackSize: 1 << 10, // 1 KB
		LogErrorFunc: func(c echo.Context, err error, stack []byte) error {
			defer sugar.Sync()
			sugar.Errorw("Api Panic", "error", err.Error())
			return c.String(500, "Internal Server Error")
		},
	}))
	db, err := sql.Open("mysql", DSN)
	err = db.Ping()
	if err != nil {
		sugar.Error(err.Error())
	}
	defer db.Close()

	client = redis.NewClient(&redis.Options{
		Addr:     "cache:6379",
		Password: "",
		DB:       0,
	})
	defer client.Close()

	e.POST("/v1/chat/completions", func(c echo.Context) error {
		cc := c.(*Context)
		defer cc.log.Sync()
		request, err := preprocessOpenaiRequest(cc, db)
		if err != nil {
			error := err.(*RequestError)
			cc.log.Error(err.Error())
			return cc.String(error.StatusCode, error.Err.Error())
		}
		cc.log.Infof("/api/chat/completions - %d\n", request.UserId)
		request.Endpoint = ENDPOINTS.CHAT
		res, err := queryMiners(cc, request.Body, "/v1/chat/completions", request.Miner)
		go saveRequest(db, res, *request, cc.log)

		if err != nil {
			cc.log.Warn(err.Error())
			return c.String(500, err.Error())
		}

		if !res.Success {
			cc.log.Warnf("Miner %d: %s %s\n Failed request\n", res.Miner.Uid, res.Miner.Hotkey, res.Miner.Coldkey)
			return c.String(500, fmt.Sprintf("Miner UID %d Failed Request. Try Again.", res.Miner.Uid))
		}

		return c.String(200, "")
	})
	e.POST("/v1/completions", func(c echo.Context) error {
		cc := c.(*Context)
		defer cc.log.Sync()
		request, err := preprocessOpenaiRequest(cc, db)
		if err != nil {
			error := err.(*RequestError)
			cc.log.Error(err.Error())
			return cc.String(error.StatusCode, error.Err.Error())
		}
		cc.log.Infof("/api/completions - %d\n", request.UserId)
		request.Endpoint = ENDPOINTS.COMPLETION
		res, err := queryMiners(cc, request.Body, "/v1/completions", request.Miner)

		go saveRequest(db, res, *request, cc.log)

		if err != nil {
			cc.log.Warn(err.Error())
			return c.String(500, err.Error())
		}

		if !res.Success {
			cc.log.Warnf("Miner %d: %s %s\n Failed request\n", res.Miner.Uid, res.Miner.Hotkey, res.Miner.Coldkey)
			return c.String(500, fmt.Sprintf("Miner UID %d Failed Request. Try Again.", res.Miner.Uid))
		}

		return c.String(200, "")
	})
	e.Logger.Fatal(e.Start(":80"))
}
