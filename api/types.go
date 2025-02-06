package main

import (
	"fmt"
	"time"
)

type RequestError struct {
	StatusCode int
	Err        error
}

func (r *RequestError) Error() string {
	return fmt.Sprintf("status %d: err %v", r.StatusCode, r.Err)
}

type RequestBody struct {
	Model string `json:"model"`
}

type Miner struct {
	Ip      string `json:"ip,omitempty"`
	Port    int    `json:"port,omitempty"`
	Hotkey  string `json:"hotkey,omitempty"`
	Coldkey string `json:"coldkey,omitempty"`
	Uid     int    `json:"uid,omitempty"`
}

type Request struct {
	Messages []ChatMessage `json:"messages"`
}

type ChatMessage struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

type RequestInfo struct {
	StartingCredits int64
	UserId          int
	Body            []byte
	Endpoint        string
	Miner           *int
	MinerHost       string
	Id              string
	StartTime       time.Time
}

// Organize Fields Dependent on Type of Response
type ResponseInfo struct {
	Miner     Miner
	Success   bool
	TotalTime int64

	Type  string
	Data  Data
	Error string
}

type Data struct {
	Image      Image
	Chat       Chat
	Completion Completion
}

type Completion struct {
	TimeToFirstToken int64
	ResponseTokens   int
	Responses        []map[string]interface{}
}

type Chat struct {
	TimeToFirstToken int64
	ResponseTokens   int
	Responses        []map[string]interface{}
}

type Image struct {
	Created float64     `json:"created"`
	Data    []ImageData `json:"data"`
}

type ImageData struct {
	B64_json string `json:"b64_json"`
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

type Model struct {
	ID      string `json:"id"`
	Object  string `json:"object"`
	Created int64  `json:"created"`
	OwnedBy string `json:"owned_by"`
}

type ModelList struct {
	Object string  `json:"object"`
	Data   []Model `json:"data"`
}

type OpenAIError struct {
	Message string `json:"message"`
	Object  string `json:"object"`
	Type    string `json:"Type"`
	Code    int    `json:"code"`
}
