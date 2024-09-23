package main

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
	Model     string        `json:"model"`
	Messages  []ChatMessage `json:"messages"`
	MaxTokens int           `json:"max_tokens"`
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

type Event struct {
	Event string                 `json:"event"`
	Id    string                 `json:"id"`
	Retry int                    `json:"retry"`
	Data  map[string]interface{} `json:"data"`
}

type ResponseInfo struct {
	Miner           Miner
	Attempt         int
	Tokens          int
	UserId          string
	StartingCredits int
	Responses        []map[string]interface{}
}
