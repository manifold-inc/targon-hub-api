package main

import (
	"database/sql"
	"fmt"
	"io"
	"log"
	"os"
	"strconv"
	"strings"

	"github.com/aidarkhanov/nanoid"
	_ "github.com/go-sql-driver/mysql"
	"github.com/google/uuid"
	"github.com/labstack/echo/v4"
	"github.com/redis/go-redis/v9"
)

var (
	HOTKEY           string
	PUBLIC_KEY       string
	PRIVATE_KEY      string
	INSTANCE_UUID    string
	DEBUG            bool

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
	INSTANCE_UUID = uuid.New().String()
	debug, present := os.LookupEnv("DEBUG")

	if !present {
		DEBUG = false
	} else {
		DEBUG, _ = strconv.ParseBool(debug)
	}

	e := echo.New()
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
		cc.Request().Header.Add("Content-Type", "application/json")
		bearer := cc.Request().Header.Get("Authorization")
		cc.Info.Println(bearer)
		c.Response().Header().Set("Content-Type", "text/event-stream; charset=utf-8")
		c.Response().Header().Set("Cache-Control", "no-cache")
		c.Response().Header().Set("Connection", "keep-alive")
		c.Response().Header().Set("X-Accel-Buffering", "no")
		cc.Info.Printf("/api/chat/completions\n")
		var (
			credits int
			userid  string
		)
		err := db.QueryRow("SELECT user.credits, user.id FROM user INNER JOIN api_key ON user.id = api_key.user_id WHERE api_key.id = ?", strings.Split(bearer, " ")[1]).Scan(&credits, &userid)
		if err == sql.ErrNoRows {
			return c.String(401, "Unauthorized")
		}
		if err != nil {
			cc.Err.Println(err)
			return c.String(500, "")
		}
		if credits < 0 {
			return c.String(403, "Out of credits")
		}
		body, _ := io.ReadAll(cc.Request().Body)
		if err != nil {
			cc.Err.Println(err)
			return c.String(500, "")
		}

		res, ok := queryMiners(cc, body)
		cc.Info.Println(res.Tokens)
		if ok != nil {
			return c.String(500, ok.Error())
		}
		_, err = db.Exec("UPDATE user SET credits=? WHERE id=?", credits-res.Tokens, userid)
		if err != nil {
			log.Println("Failed to update")
			log.Println(err)
			return c.String(200, "")
		}
		return c.String(200, "")
	})
	e.Logger.Fatal(e.Start(":80"))
}
