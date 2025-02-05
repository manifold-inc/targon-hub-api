package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"math"
	"math/rand"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/ChainSafe/go-schnorrkel"
	"github.com/google/uuid"
	"github.com/nitishm/go-rejson/v4"
	"github.com/redis/go-redis/v9"
	"go.uber.org/zap"
)

func preprocessOpenaiRequest(c *Context, db *sql.DB, endpoint string) (*RequestInfo, *RequestError) {
	c.log = c.log.With("endpoint", endpoint)
	c.Request().Header.Add("Content-Type", "application/json")
	bearer := c.Request().Header.Get("Authorization")
	c.Response().Header().Set("Cache-Control", "no-cache")
	c.Response().Header().Set("Connection", "keep-alive")
	c.Response().Header().Set("X-Accel-Buffering", "no")

	var miner, minerHost string
	if DEBUG {
		miner = c.Request().Header.Get("X-Targon-Miner-Uid")
		minerHost = c.Request().Header.Get("X-Targon-Miner-Ip")
	}

	// Conditional Header for LLM
	if endpoint == ENDPOINTS.CHAT || endpoint == ENDPOINTS.COMPLETION {
		c.Response().Header().Set("Content-Type", "text/event-stream; charset=utf-8")
	}

	var (
		credits int64
		userid  int
	)
	err := db.QueryRow("SELECT user.credits, user.id FROM user INNER JOIN api_key ON user.id = api_key.user_id WHERE api_key.id = ?", strings.Split(bearer, " ")[1]).Scan(&credits, &userid)
	if err == sql.ErrNoRows && !DEBUG {
		c.log.Warn(bearer)
		return nil, &RequestError{401, errors.New("unauthorized")}
	}
	if err != nil {
		c.log.Errorf("Error fetching user data from api key: %v", err)
		return nil, &RequestError{500, errors.New("internal server error")}
	}
	// add user id to future logs
	c.log = c.log.With("user_id", userid)
	var payload map[string]interface{}
	body, _ := io.ReadAll(c.Request().Body)
	err = json.Unmarshal(body, &payload)
	if err != nil {
		c.log.Error(err.Error())
		return nil, &RequestError{500, errors.New("internal server error")}
	}

	model, ok := payload["model"]
	if !ok {
		return nil, &RequestError{500, errors.New("model field required")}
	}

	c.log = c.log.With("model", model.(string))

	// Image Defaults - Width, Height, Prompt (NOT NULL)
	if endpoint == ENDPOINTS.IMAGE {
		if _, ok := payload["width"]; !ok {
			payload["width"] = 1024
		}
		if _, ok := payload["height"]; !ok {
			payload["height"] = 1024
		}
		if _, ok := payload["prompt"]; !ok {
			return nil, &RequestError{400, errors.New("prompt is required")}
		}
	}

	if endpoint == ENDPOINTS.CHAT {
		var req Request
		err = json.Unmarshal(body, &req)
		if err != nil {
			return nil, &RequestError{400, errors.New("targon only supports basic chat requests with `role:string` and `content:string`")}
		}
	}

	// Conditional Check for LLM
	if endpoint == ENDPOINTS.CHAT || endpoint == ENDPOINTS.COMPLETION {
		if stream, ok := payload["stream"]; !ok || !stream.(bool) {
			return nil, &RequestError{400, errors.New("targon currently only supports streaming requests")}
		}

		if val, ok := payload["seed"]; !ok || val == nil {
			payload["seed"] = rand.Intn(100000)
		}

		if _, ok := payload["temperature"]; !ok {
			payload["temperature"] = 1
		}

		if _, ok := payload["max_tokens"]; !ok {
			payload["max_tokens"] = 512
		}

		if logprobs, ok := payload["logprobs"]; !ok || !logprobs.(bool) {
			payload["logprobs"] = true
		}
	}

	body, err = json.Marshal(payload)
	if err != nil {
		c.log.Error(err.Error())
		return nil, &RequestError{500, errors.New("internal server error")}
	}

	res := &RequestInfo{Body: body, UserId: userid, StartingCredits: credits, Id: c.reqid}
	miner_uid, err := strconv.Atoi(miner)
	if err == nil {
		res.Miner = &miner_uid
	}
	res.Endpoint = endpoint
	res.MinerHost = minerHost
	return res, nil
}

func safeEnv(env string) string {
	// Lookup env variable, and panic if not present

	res, present := os.LookupEnv(env)
	if !present {
		log.Fatalf("Missing environment variable %s", env)
	}
	return res
}

func getEnv(env, fallback string) string {
	if value, ok := os.LookupEnv(env); ok {
		return value
	}
	return fallback
}

func signMessage(message []byte, public string, private string) string {
	// Signs a message via schnorrkel pub and private keys

	var pubk [32]byte
	data, err := hex.DecodeString(public)
	if err != nil {
		log.Fatalf("Failed to decode public key: %s", err)
	}
	copy(pubk[:], data)

	var prik [32]byte
	data, err = hex.DecodeString(private)
	if err != nil {
		log.Fatalf("Failed to decode private key: %s", err)
	}
	copy(prik[:], data)

	priv := schnorrkel.SecretKey{}
	_ = priv.Decode(prik)
	pub := schnorrkel.PublicKey{}
	_ = pub.Decode(pubk)

	signingCtx := []byte("substrate")
	signingTranscript := schnorrkel.NewSigningContext(signingCtx, message)
	sig, _ := priv.Sign(signingTranscript)
	sigEncode := sig.Encode()
	out := hex.EncodeToString(sigEncode[:])

	return "0x" + out
}

func sha256Hash(str []byte) string {
	h := sha256.New()
	h.Write(str)
	sum := h.Sum(nil)
	return hex.EncodeToString(sum)
}

func getMinersForModel(c *Context, model string) []Miner {
	rh := rejson.NewReJSONHandler()
	rh.SetGoRedisClientWithContext(c.Request().Context(), client)
	minerJSON, err := rh.JSONGet(model, ".")

	// Model not available
	if err == redis.Nil {
		c.log.Warnf("No miners running %s", model)
		return nil
	}
	if err == context.Canceled {
		c.log.Warn(err.Error())
		return nil
	}
	if err != nil {
		c.log.Errorw("Failed to get model from redis: "+model, "error", err.Error())
		return nil
	}

	var miners []Miner
	err = json.Unmarshal(minerJSON.([]byte), &miners)
	if err != nil {
		c.log.Errorf("Failed to JSON Unmarshal: %s\n", err.Error())
		return nil
	}
	for i := range miners {
		j := rand.Intn(i + 1)
		miners[i], miners[j] = miners[j], miners[i]
	}
	return miners
}

func queryMiners(c *Context, req *RequestInfo) (*ResponseInfo, error) {
	body := req.Body
	// Query miners with llm request
	var requestBody RequestBody
	err := json.Unmarshal(body, &requestBody)
	if err != nil {
		c.log.Errorf("Error unmarshaling request body: %s\nBody: %s\n", err.Error(), string(body))
		return nil, errors.New("invalid body")
	}

	var miner Miner

	if len(req.MinerHost) != 0 {
		host := strings.TrimPrefix(req.MinerHost, "http://")
		ip := strings.Split(host, ":")[0]
		port, _ := strconv.Atoi(strings.Split(host, ":")[1])
		miner = Miner{
			Ip:      ip,
			Port:    port,
			Hotkey:  "",
			Coldkey: "",
			Uid:     -1,
		}
	}

	// Only get miners from redis if we dont specify host
	if len(req.MinerHost) == 0 {
		miners := getMinersForModel(c, requestBody.Model)
		if len(miners) == 0 {
			return nil, errors.New("no miners")
		}

		miner = miners[0]

		// Call specific miner if passed
		if req.Miner != nil {
			c.log.Infof("Attempting to find miner %d", *req.Miner)
			found := false
			for i := range miners {
				m := miners[i]
				if m.Uid == *req.Miner {
					miner = m
					found = true
					break
				}
			}
			if !found {
				return nil, errors.New("could not find miner with uid")
			}
		}

	}

	tr := &http.Transport{
		Dial: (&net.Dialer{
			Timeout: 2 * time.Second,
		}).Dial,
		TLSHandshakeTimeout: 2 * time.Second,
		DisableKeepAlives:   false,
	}
	httpClient := http.Client{Transport: tr, Timeout: 2 * time.Minute}

	tokens := 0
	var imageResponse Image
	var llmResponse []map[string]interface{}
	var timeToFirstToken int64

	route, ok := ROUTES[req.Endpoint]
	if !ok {
		return nil, errors.New("unknown method")
	}

	endpoint := "http://" + miner.Ip + ":" + fmt.Sprint(miner.Port) + route

	// start creation of signature
	timestamp := time.Now().UnixMilli()
	id := uuid.New().String()
	timestampInterval := int64(math.Ceil(float64(timestamp) / 1e4))

	// Build the rest of the body hash
	bodyHash := sha256Hash(req.Body)
	message := fmt.Sprintf("%s.%s.%d.%s", bodyHash, id, timestamp, miner.Hotkey)
	requestSignature := signMessage([]byte(message), PUBLIC_KEY, PRIVATE_KEY)

	headers := map[string]string{
		"Epistula-Version":            "2",
		"Epistula-Timestamp":          fmt.Sprintf("%d", timestamp),
		"Epistula-Uuid":               id,
		"Epistula-Signed-By":          HOTKEY,
		"Epistula-Signed-For":         miner.Hotkey,
		"Epistula-Request-Signature":  requestSignature,
		"Epistula-Secret-Signature-0": signMessage([]byte(fmt.Sprintf("%d.%s", timestampInterval-1, miner.Hotkey)), PUBLIC_KEY, PRIVATE_KEY),
		"Epistula-Secret-Signature-1": signMessage([]byte(fmt.Sprintf("%d.%s", timestampInterval, miner.Hotkey)), PUBLIC_KEY, PRIVATE_KEY),
		"Epistula-Secret-Signature-2": signMessage([]byte(fmt.Sprintf("%d.%s", timestampInterval+1, miner.Hotkey)), PUBLIC_KEY, PRIVATE_KEY),
		"X-Targon-Model":              requestBody.Model,
		"Content-Type":                "application/json",
	}

	// Add Connection header for LLM requests
	if req.Endpoint == ENDPOINTS.COMPLETION || req.Endpoint == ENDPOINTS.CHAT {
		headers["Connection"] = "keep-alive"
	}

	r, err := http.NewRequest("POST", endpoint, bytes.NewBuffer(req.Body))
	if err != nil {
		c.log.Warnf("Failed miner request: %s\n", err.Error())
		return &ResponseInfo{Miner: miner, Success: false}, nil
	}

	// Set headers
	for key, value := range headers {
		r.Header.Set(key, value)
	}
	r.Close = true
	r = r.WithContext(c.Request().Context())

	res, err := httpClient.Do(r)
	start := time.Now()
	if err != nil {
		c.log.Warnf("Miner: %s %s\nError: %s\n", miner.Hotkey, miner.Coldkey, err.Error())
		if res != nil {
			res.Body.Close()
		}
		return &ResponseInfo{Miner: miner, Success: false}, nil
	}
	if res.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(res.Body)
		res.Body.Close()
		c.log.Warnf("Miner: %s %s\nError: %s\n", miner.Hotkey, miner.Coldkey, string(body))
		return &ResponseInfo{Miner: miner, Success: false}, nil
	}

	c.log.Infof("Miner: %s %s\n", miner.Hotkey, miner.Coldkey)
	var ri ResponseInfo

	switch req.Endpoint {
	case ENDPOINTS.CHAT, ENDPOINTS.COMPLETION:
		reader := bufio.NewScanner(res.Body)
		finished := false
		for reader.Scan() {
			select {
			case <-c.Request().Context().Done():
				return &ResponseInfo{}, errors.New("request canceled")
			default:
				token := reader.Text()
				fmt.Fprint(c.Response(), token+"\n\n")
				c.Response().Flush()
				if token == "data: [DONE]" {
					finished = true
					break
				}
				token, found := strings.CutPrefix(token, "data: ")
				if found {
					if tokens == 0 {
						timeToFirstToken = int64(time.Since(start) / time.Millisecond)
					}
					tokens += 1
					var response map[string]interface{}
					err := json.Unmarshal([]byte(token), &response)
					if err != nil {
						c.log.Errorf("Failed decoding token string: %s - Token: %s", err.Error(), token)
						continue
					}
					llmResponse = append(llmResponse, response)
				}
			}
		}
		res.Body.Close()
		if !finished {
			if req.Endpoint == ENDPOINTS.CHAT {
				return &ResponseInfo{Miner: miner, Data: Data{Chat: Chat{ResponseTokens: tokens, TimeToFirstToken: timeToFirstToken, Responses: llmResponse}}, Success: false, Type: ENDPOINTS.CHAT}, nil
			}
			return &ResponseInfo{Miner: miner, Data: Data{Completion: Completion{ResponseTokens: tokens, TimeToFirstToken: timeToFirstToken, Responses: llmResponse}}, Success: false, Type: ENDPOINTS.COMPLETION}, nil
		}
		ri = ResponseInfo{
			Miner:   miner,
			Success: true,

			Type: req.Endpoint,
		}
		if req.Endpoint == ENDPOINTS.CHAT {
			ri.Data = Data{Chat: Chat{Responses: llmResponse, ResponseTokens: tokens, TimeToFirstToken: timeToFirstToken}}
		}
		if req.Endpoint == ENDPOINTS.COMPLETION {
			ri.Data = Data{Completion: Completion{Responses: llmResponse, ResponseTokens: tokens, TimeToFirstToken: timeToFirstToken}}
		}
	case ENDPOINTS.IMAGE:
		responseBytes, err := io.ReadAll(res.Body)
		if err != nil {
			c.log.Errorf("Failed to read image response: %s", err.Error())
			return &ResponseInfo{Miner: miner, Success: false, Type: ENDPOINTS.IMAGE}, nil
		}

		err = json.Unmarshal(responseBytes, &imageResponse)
		if err != nil {
			c.log.Errorf("Failed decoding image json: %s", string(responseBytes))
		}
		res.Body.Close()
		ri = ResponseInfo{
			Miner:   miner,
			Success: true,

			Type: ENDPOINTS.IMAGE,
			Data: Data{Image: imageResponse},
		}
	default:
		return nil, errors.New("unknown method")
	}

	totalTime := int64(time.Since(start) / time.Millisecond)
	ri.TotalTime = totalTime
	c.log.Infof("Finished Request in %dms", totalTime, "final", true)
	return &ri, nil
}

func saveRequest(db *sql.DB, res *ResponseInfo, req *RequestInfo, logger *zap.SugaredLogger) {
	var (
		model_id int
		cpt      int
	)
	var bodyJson map[string]interface{}
	err := json.Unmarshal(req.Body, &bodyJson)
	if err != nil {
		logger.Warnf("Failed unmasrhaling request body: %s", string(req.Body))
		return
	}
	model, ok := bodyJson["model"]
	if !ok {
		logger.Error("No model in body")
		return
	}
	err = db.QueryRow("SELECT id, cpt FROM model WHERE name = ?", model.(string)).Scan(&model_id, &cpt)
	if err != nil {
		logger.Warnw("Failed to get model "+model.(string), "error", err.Error())
		return
	}

	// Re-add later vv

	// Update credits
	// usedCredits := res.ResponseTokens * cpt
	//_, err = db.Exec("UPDATE user SET credits=? WHERE id=?",
	//	max(req.StartingCredits-int64(usedCredits), 0),
	//	req.UserId)
	//if err != nil {
	//	logger.Errorf("Failed to update credits: %d - %d\n%s\n", req.StartingCredits, usedCredits, err)
	//}

	var responseJson []byte
	var timeForFirstToken int64 = 0
	switch res.Type {
	case ENDPOINTS.CHAT:
		timeForFirstToken = res.Data.Chat.TimeToFirstToken
		responseJson, err = json.Marshal(res.Data.Chat.Responses)
	case ENDPOINTS.COMPLETION:
		timeForFirstToken = res.Data.Chat.TimeToFirstToken
		responseJson, err = json.Marshal(res.Data.Completion.Responses)
	case ENDPOINTS.IMAGE:
		responseJson, err = json.Marshal(res.Data.Image)
	}

	if err != nil {
		logger.Errorw("Failed to parse json: "+string(responseJson), "error", err.Error())
	}

	_, err = db.Exec(`
	INSERT INTO 
		request (pub_id, user_id, credits_used, request, response, model_id, uid, hotkey, coldkey, miner_address, endpoint, success, time_to_first_token, total_time, scored)
		VALUES	(?,      ?,       ?,            ?,       ?,        ?,        ?,   ?,      ?,       ?,             ?,        ?,       ?,                   ?,          ?)`,
		req.Id,
		req.UserId,
		0,
		string(req.Body),
		NewNullString(string(responseJson)),
		model_id,
		res.Miner.Uid,
		res.Miner.Hotkey,
		res.Miner.Coldkey,
		fmt.Sprintf("http://%s:%d",
			res.Miner.Ip,
			res.Miner.Port),
		req.Endpoint,
		res.Success,
		timeForFirstToken,
		res.TotalTime,
		req.Miner != nil,
	)
	if err != nil {
		logger.Errorw("Failed to update", "error", err.Error())
		return
	}
}

func QueryFallback(c *Context, db *sql.DB, req *RequestInfo) *RequestError {
	var requestBody RequestBody
	err := json.Unmarshal(req.Body, &requestBody)
	if err != nil {
		c.log.Errorw("Error unmarshaling request body", "error", err.Error())
		return &RequestError{400, errors.New("invalid body")}
	}
	var fallback_server string
	err = db.QueryRow("SELECT model.fallback_server FROM model WHERE model.name = ?", requestBody.Model).Scan(&fallback_server)
	if err == sql.ErrNoRows && !DEBUG {
		return &RequestError{400, fmt.Errorf("no model found for %s", requestBody.Model)}
	}
	if err != nil {
		return &RequestError{500, errors.New("internal server error")}
	}
	headers := map[string]string{
		"X-Targon-Model": requestBody.Model,
		"Authorization":  fmt.Sprintf("Bearer %s", FALLBACK_API_KEY),
	}

	// Add Connection header for LLM requests
	if req.Endpoint == ENDPOINTS.COMPLETION || req.Endpoint == ENDPOINTS.CHAT {
		headers["Connection"] = "keep-alive"
	}

	route := ROUTES[req.Endpoint]
	r, err := http.NewRequest("POST", fallback_server+route, bytes.NewBuffer(req.Body))
	if err != nil {
		c.log.Warnw("Failed building fallback request", "error", err.Error())
	}

	// Set headers
	for key, value := range headers {
		r.Header.Set(key, value)
	}
	r.Close = true
	r = r.WithContext(c.Request().Context())

	tr := &http.Transport{
		Dial: (&net.Dialer{
			Timeout: 2 * time.Second,
		}).Dial,
		TLSHandshakeTimeout: 2 * time.Second,
		DisableKeepAlives:   false,
	}
	httpClient := http.Client{Transport: tr, Timeout: 2 * time.Minute}
	res, err := httpClient.Do(r)
	start := time.Now()
	if res != nil {
		defer res.Body.Close()
	}
	if err != nil {
		c.log.Warnw("Fallback request failed", "error", err)
		return &RequestError{429, errors.New("fallback request failed")}
	}
	if res.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(res.Body)
		res.Body.Close()
		c.log.Warnw("Fallback request failed", "error", body)
		return &RequestError{429, errors.New("fallback request failed")}
	}
	reader := bufio.NewScanner(res.Body)

scanner:
	for reader.Scan() {
		select {
		case <-c.Request().Context().Done():
			return &RequestError{400, errors.New("request canceled")}
		default:
			token := reader.Text()
			fmt.Fprint(c.Response(), token+"\n\n")
			c.Response().Flush()
			if token == "data: [DONE]" {
				break scanner
			}
		}
	}
	totalTime := int64(time.Since(start) / time.Millisecond)
	c.log.Infof("Finished fallback request in %dms", totalTime, "final", true)
	return nil
}

func NewNullString(s string) sql.NullString {
	if len(s) == 0 {
		return sql.NullString{}
	}
	return sql.NullString{
		String: s,
		Valid:  true,
	}
}
