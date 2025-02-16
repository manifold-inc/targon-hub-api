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
	"github.com/jmcvetta/randutil"
	"github.com/nitishm/go-rejson/v4"
	"github.com/redis/go-redis/v9"
	"go.uber.org/zap"
)

// TODO figure out params
// Returns true / false for allowed / rate limited
const REQUESTS_PER_HOUR = 60 * 30
func CheckRateLimit() (bool, error) {
	// TODO check if user is rate limited
	// TODO log connection for future rate limit checks
	return false, nil
}

func preprocessOpenaiRequest(
	c *Context,
	db *sql.DB,
	endpoint string,
) (*RequestInfo, *RequestError) {
	startTime := time.Now()
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
	err := db.QueryRow("SELECT user.credits, user.id FROM user INNER JOIN api_key ON user.id = api_key.user_id WHERE api_key.id = ?", strings.Split(bearer, " ")[1]).
		Scan(&credits, &userid)
	if err == sql.ErrNoRows && !DEBUG {
		c.log.Warnf("no user found for bearer token %s", bearer)
		return nil, &RequestError{401, errors.New("unauthorized")}
	}
	if err != nil {
		c.log.Errorf("Error fetching user data from api key", "error", err)
		return nil, &RequestError{500, errors.New("internal server error")}
	}
	// add user id to future logs
	c.log = c.log.With("user_id", userid)

	// TODO rate limit

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
			return nil, &RequestError{
				400,
				errors.New(
					"targon only supports basic chat requests with `role:string` and `content:string`",
				),
			}
		}
	}

	// Conditional Check for LLM
	if endpoint == ENDPOINTS.CHAT || endpoint == ENDPOINTS.COMPLETION {
		if stream, ok := payload["stream"]; !ok || !stream.(bool) {
			return nil, &RequestError{
				400,
				errors.New("targon currently only supports streaming requests"),
			}
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
		payload["stream_options"] = map[string]interface{}{
			"include_usage": true,
		}
	}

	body, err = json.Marshal(payload)
	if err != nil {
		c.log.Errorw("Failed re-marshaling request", "error", err.Error())
		return nil, &RequestError{500, errors.New("internal server error")}
	}

	res := &RequestInfo{Body: body, UserId: userid, StartingCredits: credits, Id: c.reqid}
	miner_uid, err := strconv.Atoi(miner)
	if err == nil {
		res.Miner = &miner_uid
	}
	res.Endpoint = endpoint
	res.MinerHost = minerHost
	res.StartTime = startTime
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

func getMinerForModel(c *Context, model string, specific_uid *int) (*Miner, error) {
	// Weighted random based on miner incentive
	rh := rejson.NewReJSONHandler()
	rh.SetGoRedisClientWithContext(c.Request().Context(), REDIS_CLIENT)
	minerJSON, err := rh.JSONGet(model, ".")
	var choices []randutil.Choice

	// Model not available
	if err == redis.Nil {
		c.log.Warnf("No miners running %s", model)
		return nil, errors.New("no miners")
	}
	if err == context.Canceled {
		c.log.Warn("Request canceled")
		return nil, errors.New("request canceled")
	}
	if err != nil {
		c.log.Errorw("Failed to get model from redis", "error", err.Error())
		return nil, errors.New("failed to get miners from redis")
	}

	var miners []Miner
	err = json.Unmarshal(minerJSON.([]byte), &miners)
	if err != nil {
		c.log.Errorw("Failed to JSON Unmarshal", "error", err.Error())
		return nil, errors.New("failed to unmarshall json")
	}
	for i := range miners {
		if specific_uid != nil && miners[i].Uid == *specific_uid {
			return &miners[i], nil
		}
		ch := randutil.Choice{Item: miners[i], Weight: int(miners[i].IncentiveScaled)}
		choices = append(choices, ch)
	}
	choice, err := randutil.WeightedChoice(choices)
	if err != nil {
		c.log.Errorw("Failed getting weighted random choice", "error", err.Error())
		return &miners[0], nil
	}
	miner := choice.Item.(Miner)
	return &miner, nil
}

func queryMiners(c *Context, req *RequestInfo) (*ResponseInfo, error) {
	body := req.Body
	// Query miners with llm request
	var requestBody RequestBody
	err := json.Unmarshal(body, &requestBody)
	if err != nil {
		c.log.Errorf(
			fmt.Sprintf("Error unmarshaling request body: %s", string(body)),
			"error",
			err.Error(),
		)
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
		m, err := getMinerForModel(c, requestBody.Model, req.Miner)
		if err != nil {
			return nil, errors.New("no miners")
		}
		miner = *m
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
		"Epistula-Version":           "2",
		"Epistula-Timestamp":         fmt.Sprintf("%d", timestamp),
		"Epistula-Uuid":              id,
		"Epistula-Signed-By":         HOTKEY,
		"Epistula-Signed-For":        miner.Hotkey,
		"Epistula-Request-Signature": requestSignature,
		"Epistula-Secret-Signature-0": signMessage(
			[]byte(fmt.Sprintf("%d.%s", timestampInterval-1, miner.Hotkey)),
			PUBLIC_KEY,
			PRIVATE_KEY,
		),
		"Epistula-Secret-Signature-1": signMessage(
			[]byte(fmt.Sprintf("%d.%s", timestampInterval, miner.Hotkey)),
			PUBLIC_KEY,
			PRIVATE_KEY,
		),
		"Epistula-Secret-Signature-2": signMessage(
			[]byte(fmt.Sprintf("%d.%s", timestampInterval+1, miner.Hotkey)),
			PUBLIC_KEY,
			PRIVATE_KEY,
		),
		"X-Targon-Model": requestBody.Model,
		"Content-Type":   "application/json",
	}

	// Add Connection header for LLM requests
	if req.Endpoint == ENDPOINTS.COMPLETION || req.Endpoint == ENDPOINTS.CHAT {
		headers["Connection"] = "keep-alive"
	}

	r, err := http.NewRequest("POST", endpoint, bytes.NewBuffer(req.Body))
	if err != nil {
		return &ResponseInfo{Miner: miner, Success: false, Error: err.Error()}, nil
	}

	// Set headers
	for key, value := range headers {
		r.Header.Set(key, value)
	}
	r.Close = true
	r = r.WithContext(c.Request().Context())

	ctx, cancel := context.WithCancel(c.Request().Context())
	defer cancel()
	var timer *time.Timer

	if req.Endpoint == ENDPOINTS.CHAT || req.Endpoint == ENDPOINTS.COMPLETION {
		r = r.WithContext(ctx)
		timer = time.AfterFunc(4*time.Second, func() {
			cancel()
		})
	}

	res, err := httpClient.Do(r)
	start := time.Now()
	if err != nil {
		if res != nil {
			res.Body.Close()
		}
		return &ResponseInfo{Miner: miner, Success: false, Error: err.Error()}, nil
	}
	if res.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(res.Body)
		res.Body.Close()
		return &ResponseInfo{Miner: miner, Success: false, Error: string(body)}, nil
	}

	c.log.Infow(
		"Sending organic to miner",
		"hotkey",
		miner.Hotkey,
		"coldkey",
		miner.Coldkey,
		"uid",
		miner.Uid,
	)
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
				timer.Stop()
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
						c.log.Infow(
							"time to first token",
							"duration",
							fmt.Sprintf("%d", time.Since(req.StartTime)/time.Millisecond),
							"from",
							"miner",
						)
					}
					tokens += 1
					var response map[string]interface{}
					err := json.Unmarshal([]byte(token), &response)
					if err != nil {
						c.log.Warnw(
							fmt.Sprintf("Failed decoding token %s", token),
							"error", err.Error(),
						)
						continue
					}
					llmResponse = append(llmResponse, response)
				}
			}
		}
		res.Body.Close()
		if !finished {
			if req.Endpoint == ENDPOINTS.CHAT {
				return &ResponseInfo{
					Miner: miner,
					Data: Data{
						Chat: Chat{
							ResponseTokens:   tokens,
							TimeToFirstToken: timeToFirstToken,
							Responses:        llmResponse,
						},
					},
					Success: false,
					Type:    ENDPOINTS.CHAT,
				}, nil
			}
			return &ResponseInfo{
				Miner: miner,
				Data: Data{
					Completion: Completion{
						ResponseTokens:   tokens,
						TimeToFirstToken: timeToFirstToken,
						Responses:        llmResponse,
					},
				},
				Success: false,
				Type:    ENDPOINTS.COMPLETION,
			}, nil
		}
		ri = ResponseInfo{
			Miner:   miner,
			Success: true,

			Type: req.Endpoint,
		}
		if req.Endpoint == ENDPOINTS.CHAT {
			ri.Data = Data{
				Chat: Chat{
					Responses:        llmResponse,
					ResponseTokens:   tokens,
					TimeToFirstToken: timeToFirstToken,
				},
			}
		}
		if req.Endpoint == ENDPOINTS.COMPLETION {
			ri.Data = Data{
				Completion: Completion{
					Responses:        llmResponse,
					ResponseTokens:   tokens,
					TimeToFirstToken: timeToFirstToken,
				},
			}
		}
	case ENDPOINTS.IMAGE:
		responseBytes, err := io.ReadAll(res.Body)
		if err != nil {
			c.log.Errorw("Failed to read image response", "error", err.Error())
			return &ResponseInfo{Miner: miner, Success: false, Type: ENDPOINTS.IMAGE}, nil
		}

		err = json.Unmarshal(responseBytes, &imageResponse)
		if err != nil {
			c.log.Errorf("Failed decoding image json", "error", string(responseBytes))
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
	c.log.Infow(
		"Finished Request",
		"final", "true",
		"status", "success",
		"duration", fmt.Sprintf("%d", time.Since(req.StartTime)/time.Millisecond),
		"tokens", tokens,
	)
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
	err = db.QueryRow("SELECT id, cpt FROM model WHERE name = ?", model.(string)).
		Scan(&model_id, &cpt)
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
	err = db.QueryRow("SELECT model.fallback_server FROM model WHERE model.name = ?", requestBody.Model).
		Scan(&fallback_server)
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

	tokens := 0
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
			if _, found := strings.CutPrefix(token, "data: "); found {
				if tokens == 0 {
					c.log.Infow("time to first token", "duration", fmt.Sprintf("%d", time.Since(req.StartTime)/time.Millisecond), "from", "fallback")
				}
				tokens += 1
			}
		}
	}
	c.log.Infow(
		"Finished fallback request",
		"final", "true",
		"status", "success",
		"duration", fmt.Sprintf("%d", time.Since(req.StartTime)/time.Millisecond),
		"tokens", tokens,
	)
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
