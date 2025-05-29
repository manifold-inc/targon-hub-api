package shared

import (
	"fmt"
	"time"

	"api/internal/config"

	"github.com/labstack/echo/v4"
	"go.uber.org/zap"
)

type Context struct {
	echo.Context
	Log   *zap.SugaredLogger
	Reqid string
	Cfg   *config.Config
	ExternalId string
}

type OpenAIError struct {
	Message string `json:"message"`
	Object  string `json:"object"`
	Type    string `json:"Type"`
	Code    int    `json:"code"`
}

type Endpoints struct {
	CHAT       string
	COMPLETION string
	IMAGE      string
}

var ENDPOINTS = Endpoints{CHAT: "CHAT", COMPLETION: "COMPLETION", IMAGE: "IMAGE"}

var ROUTES = map[string]string{
	ENDPOINTS.CHAT:       "/v1/chat/completions",
	ENDPOINTS.COMPLETION: "/v1/completions",
	ENDPOINTS.IMAGE:      "/v1/images/generations",
}

type RequestError struct {
	StatusCode int
	Err        error
}

func (r *RequestError) Error() string {
	return fmt.Sprintf("status %d: err %v", r.StatusCode, r.Err)
}

type RequestInfo struct {
	StartingCredits int64
	UserId          int
	Body            []byte
	Endpoint        string
	Id              string
	StartTime       time.Time
	Chargeable      bool
	Model           string
}

// Organize Fields Dependent on Type of Response
type ResponseInfo struct {
	TotalTime            int32
	TimeToFirstToken     int32
	ResponseTokens       int
	ResponseTokensString string
}

type Request struct {
	MaxTokens uint64        `json:"max_tokens"`
	Model     string        `json:"model"`
}
