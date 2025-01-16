package main

import "fmt"

type RequestError struct {
	StatusCode int
	Err        error
}

func (r *RequestError) Error() string {
	return fmt.Sprintf("status %d: err %v", r.StatusCode, r.Err)
}

type Response struct {
	Id      string   `json:"id"`
	Model   string   `json:"model"`
	Choices []Choice `json:"choices"`
}
type Choice struct {
	Delta Delta `json:"delta"`
}
type Delta struct {
	Content *string `json:"content"`
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

type Epistula struct {
	Data      InferenceBody `json:"data"`
	Nonce     int64         `json:"nonce"`
	SignedBy  string        `json:"signed_by"`
	SignedFor string        `json:"signed_for"`
}

type InferenceBody struct {
	Messages    []ChatMessage `json:"messages"`
	Temperature float32       `json:"temperature"`
	Model       string        `json:"model"`
	MaxTokens   int           `json:"max_tokens"`
	Stream      bool          `json:"stream"`
	Logprobs    bool          `json:"logprobs"`
}

type ChatMessage struct {
	Role    string `json:"role"`
	Content string `json:"content"`
	Name    string `json:"name,omitempty"`
}

type RequestInfo struct {
	StartingCredits int64
	UserId          int
	Body            []byte
	Endpoint        string
	Miner           *int
	Id              string
}

// Organize Fields Dependent on Type of Response
type ResponseInfo struct {
	Miner     Miner
	Success   bool
	TotalTime int64

	Type string
	Data Data
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

