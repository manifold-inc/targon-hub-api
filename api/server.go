package main

import (
	"database/sql"
	"fmt"
	"log"
	"os"
	"strconv"

	"github.com/aidarkhanov/nanoid"
	_ "github.com/go-sql-driver/mysql"
	"github.com/google/uuid"
	"github.com/labstack/echo/v4/middleware"
	"github.com/labstack/echo/v4"
	"github.com/redis/go-redis/v9"
)

var (
	HOTKEY        string
	PUBLIC_KEY    string
	PRIVATE_KEY   string
	INSTANCE_UUID string
	ENDON_URL     string
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
	Info  *log.Logger
	Warn  *log.Logger
	Err   *log.Logger
	reqid string
}

func main() {
	HOTKEY = safeEnv("HOTKEY")
	PUBLIC_KEY = safeEnv("PUBLIC_KEY")
	PRIVATE_KEY = safeEnv("PRIVATE_KEY")
	DSN := safeEnv("DSN")
	ENDON_URL = safeEnv("ENDON_URL")
	INSTANCE_UUID = uuid.New().String()
	debug, present := os.LookupEnv("DEBUG")

	if !present {
		DEBUG = false
	} else {
		DEBUG, _ = strconv.ParseBool(debug)
	}

	e := echo.New()
	e.Use(middleware.CORS())
	e.Use(func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			reqId, _ := nanoid.Generate("0123456789abcdefghijklmnopqrstuvwxyz", 12)
			InfoLog := log.New(os.Stdout, fmt.Sprintf("%sINFO [%s]: %s", Green, reqId, Reset), log.Ldate|log.Ltime|log.Lshortfile)
			WarnLog := log.New(os.Stdout, fmt.Sprintf("%sWARNING [%s]: %s", Yellow, reqId, Reset), log.Ldate|log.Ltime|log.Lshortfile)
			ErrLog := log.New(os.Stdout, fmt.Sprintf("%sERROR [%s]: %s", Red, reqId, Reset), log.Ldate|log.Ltime|log.Lshortfile)
			cc := &Context{c, InfoLog, WarnLog, ErrLog, reqId}
			return next(cc)
		}
	})
	var err error
	db, err := sql.Open("mysql", DSN)
	err = db.Ping()
	if err != nil {
		log.Println(err.Error())
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
		request, err := preprocessOpenaiRequest(cc, db)
		cc.Info.Printf("/api/chat/completions - %d\n", request.UserId)
		if err != nil {
			error := err.(*RequestError)
			cc.Err.Println(err)
			return cc.String(error.StatusCode, error.Err.Error())
		}
		request.Endpoint = "CHAT"
		cc.Info.Println(string(request.Body))
		res, err := queryMiners(cc, request.Body, "/v1/chat/completions", request.Miner)
		go saveRequest(db, res, *request, cc.Err)

		if err != nil {
			cc.Err.Println(err.Error())
			sendErrorToEndon(err, "/v1/chat/completions")
			return c.String(500, err.Error())
		}

		if !res.Success {
			cc.Warn.Printf("Miner: %s %s\n Failed request\n", res.Miner.Hotkey, res.Miner.Coldkey, res.Miner.Uid)
			return c.String(500, fmt.Sprintf("Miner UID %d Failed Request. Try Again.", res.Miner.Uid))
		}

		return c.String(200, "")
	})
	e.POST("/v1/completions", func(c echo.Context) error {
		cc := c.(*Context)
		request, err := preprocessOpenaiRequest(cc, db)
		cc.Info.Printf("/api/completions - %d\n", request.UserId)
		if err != nil {
			error := err.(*RequestError)
			cc.Err.Println(err)
			return cc.String(error.StatusCode, error.Err.Error())
		}
		request.Endpoint = "COMPLETION"
		res, err := queryMiners(cc, request.Body, "/v1/completions", request.Miner)

		go saveRequest(db, res, *request, cc.Err)

		if err != nil {
			cc.Err.Println(err.Error())
			sendErrorToEndon(err, "/v1/completions")
			return c.String(500, err.Error())
		}

		if !res.Success {
			cc.Warn.Printf("Miner: %s %s\n Failed request\n", res.Miner.Hotkey, res.Miner.Coldkey, res.Miner.Uid)
			return c.String(500, fmt.Sprintf("Miner UID %d Failed Request. Try Again.", res.Miner.Uid))
		}

		return c.String(200, "")
	})
	e.Logger.Fatal(e.Start(":80"))
}
