package config

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"os"
	"strconv"

	_ "github.com/go-sql-driver/mysql"

	"github.com/google/uuid"
	"github.com/redis/go-redis/v9"
)

type Config struct {
	Env         Environment
	RedisClient *redis.Client
	SqlClient   *sql.DB
}

func (c *Config) Shutdown() {
	if c.RedisClient != nil {
		c.RedisClient.Close()
	}
	if c.SqlClient != nil {
		c.SqlClient.Close()
	}
}

type Environment struct {
	Hotkey         string
	PublicKey      string
	PrivateKey     string
	FallbackApiKey string
	InstanceUUID   string
	Debug          bool
}

func safeEnv(env string) (string, error) {
	// Lookup env variable, and panic if not present
	res, present := os.LookupEnv(env)
	if !present {
		return "", fmt.Errorf("missing environment variable %s", env)
	}
	return res, nil
}

func getEnv(env, fallback string) string {
	if value, ok := os.LookupEnv(env); ok {
		return value
	}
	return fallback
}

func InitConfig() (*Config, []error) {
	var errs []error

	// Grab ENV Variables
	HOTKEY, err := safeEnv("HOTKEY")
	if err != nil {
		errs = append(errs, err)
	}
	PUBLIC_KEY, err := safeEnv("PUBLIC_KEY")
	if err != nil {
		errs = append(errs, err)
	}
	PRIVATE_KEY, err := safeEnv("PRIVATE_KEY")
	if err != nil {
		errs = append(errs, err)
	}
	FALLBACK_API_KEY, err := safeEnv("FALLBACK_API_KEY")
	if err != nil {
		errs = append(errs, err)
	}
	DSN, err := safeEnv("DSN")
	if err != nil {
		errs = append(errs, err)
	}
	REDIS_HOST := getEnv("REDIS_HOST", "cache")
	REDIS_PORT := getEnv("REDIS_PORT", "6379")
	INSTANCE_UUID := uuid.New().String()
	DEBUG, err := strconv.ParseBool(getEnv("DEBUG", "false"))
	if err != nil {
		errs = append(errs, err)
	}

	// Error on missing env variables
	if len(errs) != 0 {
		return nil, errs
	}

	// Load DB connections
	sqlClient, err := sql.Open("mysql", DSN)
	if err != nil {
		return nil, []error{errors.New("failed initializing sqlClient"), err}
	}
	err = sqlClient.Ping()
	if err != nil {
		return nil, []error{errors.New("failed ping to sql db"), err}
	}

	redisClient := redis.NewClient(&redis.Options{
		Addr:     fmt.Sprintf("%s:%s", REDIS_HOST, REDIS_PORT),
		Password: "",
		DB:       0,
	})
	if err := redisClient.Ping(context.Background()).Err(); err != nil {
		return nil, []error{errors.New("failed ping to redis db"), err}
	}

	return &Config{
		Env: Environment{
			Hotkey:         HOTKEY,
			PublicKey:      PUBLIC_KEY,
			PrivateKey:     PRIVATE_KEY,
			FallbackApiKey: FALLBACK_API_KEY,
			InstanceUUID:   INSTANCE_UUID,
			Debug:          DEBUG,
		},
		SqlClient:   sqlClient,
		RedisClient: redisClient,
	}, nil
}
