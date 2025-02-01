package main

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"net/http"
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
	HOTKEY        string
	PUBLIC_KEY    string
	PRIVATE_KEY   string
	INSTANCE_UUID string
	DEBUG         bool

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
		request, err := preprocessOpenaiRequest(cc, db, ENDPOINTS.CHAT)
		if err != nil {
			error := err.(*RequestError)
			cc.log.Error(err.Error())
			return cc.String(error.StatusCode, error.Err.Error())
		}
		res, err := queryMiners(cc, *request)
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
		defer func() {
			_ = cc.log.Sync()
		}()
		request, err := preprocessOpenaiRequest(cc, db, ENDPOINTS.COMPLETION)
		if err != nil {
			error := err.(*RequestError)
			cc.log.Error(err.Error())
			return cc.String(error.StatusCode, error.Err.Error())
		}
		res, err := queryMiners(cc, *request)

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

	e.POST("/v1/images/generations", func(c echo.Context) error {
		cc := c.(*Context)
		defer func() {
			_ = cc.log.Sync()
		}()
		request, err := preprocessOpenaiRequest(cc, db, ENDPOINTS.IMAGE)
		if err != nil {
			error := err.(*RequestError)
			cc.log.Error(err.Error())
			return cc.String(error.StatusCode, error.Err.Error())
		}
		res, err := queryMiners(cc, *request)

		go saveRequest(db, res, *request, cc.log)

		if err != nil {
			cc.log.Warn(err.Error())
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

		// 1. Get enabled models with formatted created_at
		rows, err := db.Query(`
			SELECT 
				name, 
				DATE_FORMAT(created_at, '%Y-%m-%d %H:%i:%s') as created_at,
				modality,
				description
			FROM model 
			WHERE enabled = 1
		`)
		if err != nil {
			cc.log.Error("Failed to get models: " + err.Error())
			return c.String(500, "Failed to get models")
		}
		defer rows.Close()

		var dbModels []dbModel
		for rows.Next() {
			var m dbModel
			var createdAtStr string
			var modality string
			var description string

			if err := rows.Scan(&m.ID, &createdAtStr, &modality, &description); err != nil {
				cc.log.Error("Failed to scan model row: " + err.Error())
				continue
			}

			// Parse formatted timestamp
			createdAt, err := time.Parse("2006-01-02 15:04:05", createdAtStr)
			if err != nil {
				cc.log.Errorf("Failed to parse created_at for %s: %v", m.ID, err)
				continue
			}

			m.CreatedAt = createdAt
			m.Modality = modality
			m.Description = description
			dbModels = append(dbModels, m)
		}

		// 2. Query Hugging Face for each model
		client := &http.Client{Timeout: 10 * time.Second}
		var models []Model

		for _, dbModel := range dbModels {
			// Add Authorization header for HuggingFace API
			req, err := http.NewRequest("GET",
				fmt.Sprintf("https://huggingface.co/api/models/%s", dbModel.ID),
				nil,
			)
			if err != nil {
				cc.log.Errorf("Failed to create request for %s: %v", dbModel.ID, err)
				continue
			}

			req.Header.Add("Authorization", "Bearer "+os.Getenv("HUGGINGFACE_TOKEN"))

			resp, err := client.Do(req)
			if err != nil {
				cc.log.Errorf("Failed to fetch %s: %v", dbModel.ID, err)
				continue
			}
			defer resp.Body.Close()

			if resp.StatusCode != http.StatusOK {
				cc.log.Errorf("HuggingFace API error for %s: status %d", dbModel.ID, resp.StatusCode)
				continue
			}

			var hfData HuggingFaceData
			if err := json.NewDecoder(resp.Body).Decode(&hfData); err != nil {
				cc.log.Errorf("Failed to decode %s: %v", dbModel.ID, err)
				// Use fallback values instead of skipping
				models = append(models, Model{
					ID:            dbModel.ID,
					Name:          strings.Split(dbModel.ID, "/")[1],
					Object:        "model",
					Created:       dbModel.CreatedAt.Unix(),
					OwnedBy:       strings.Split(dbModel.ID, "/")[0],
					Description:   dbModel.Description,
					ContextLength: 4096, // Default fallback
					Architecture: Architecture{
						Modality:     mapModality(dbModel.Modality),
						Tokenizer:    "unknown",
						InstructType: nil,
					},
					Pricing: Pricing{
						Prompt:     "0",
						Completion: "0",
						Image:      "0",
						Request:    "0",
					},
					TopProvider: TopProvider{
						ContextLength:       4096, // Default fallback
						MaxCompletionTokens: 2048, // Default fallback
						IsModerated:         false,
					},
				})
				continue
			}

			// 3. Build combined response
			contextLength := 4096
			if hfData.Config.MaxPositionEmbeddings > 0 {
				contextLength = hfData.Config.MaxPositionEmbeddings
			}

			tokenizer := "unknown"
			if hfData.TokenizerConfig.TokenizerClass != "" {
				tokenizer = hfData.TokenizerConfig.TokenizerClass
			}

			models = append(models, Model{
				ID:            dbModel.ID,
				Name:          strings.Split(dbModel.ID, "/")[1],
				Object:        "model",
				Created:       dbModel.CreatedAt.Unix(),
				OwnedBy:       strings.Split(dbModel.ID, "/")[0],
				Description:   dbModel.Description,
				ContextLength: contextLength,
				Architecture: Architecture{
					Modality:     mapModality(dbModel.Modality),
					Tokenizer:    tokenizer,
					InstructType: nil,
				},
				Pricing: Pricing{
					Prompt:     "0",
					Completion: "0",
					Image:      "0",
					Request:    "0",
				},
				TopProvider: TopProvider{
					ContextLength:       contextLength,
					MaxCompletionTokens: getMaxCompletionTokens(&hfData),
					IsModerated:         false,
				},
			})
		}

		return c.JSON(200, ModelList{
			Object: "list",
			Data:   models,
		})
	})

	e.Logger.Fatal(e.Start(":80"))
}
