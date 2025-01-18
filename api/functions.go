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
	"go.uber.org/zap"
)

func preprocessOpenaiRequest(c *Context, db *sql.DB, endpoint string) (*RequestInfo, error) {
	c.log = c.log.With("endpoint", endpoint)
	c.Request().Header.Add("Content-Type", "application/json")
	bearer := c.Request().Header.Get("Authorization")
	miner := c.Request().Header.Get("X-Targon-Miner-Uid")
	c.Response().Header().Set("Cache-Control", "no-cache")
	c.Response().Header().Set("Connection", "keep-alive")
	c.Response().Header().Set("X-Accel-Buffering", "no")

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
		return nil, &RequestError{401, errors.New("Unauthorized")}
	}
	if err != nil {
		c.log.Errorf("Error fetching user data from api key: %v", err)
		return nil, &RequestError{500, errors.New("internal server error")}
	}
	var payload map[string]interface{}
	body, _ := io.ReadAll(c.Request().Body)
	err = json.Unmarshal(body, &payload)
	if err != nil {
		c.log.Error(err.Error())
		return nil, &RequestError{500, errors.New("internal server error")}
	}

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

	// Conditional Check for LLM
	if endpoint == ENDPOINTS.CHAT || endpoint == ENDPOINTS.COMPLETION {
		if stream, ok := payload["stream"]; !ok || !stream.(bool) {
			return nil, &RequestError{400, errors.New("targon currently only supports streaming requests")}
		}

		if _, ok := payload["seed"]; !ok {
			payload["seed"] = rand.Intn(100000)
		}

		if _, ok := payload["temperature"]; !ok {
			payload["temperature"] = 1
		}

		if _, ok := payload["max_tokens"]; !ok {
			payload["max_tokens"] = 512
		} else if credits < int64(payload["max_tokens"].(float64)) {
			return nil, &RequestError{403, errors.New("out of credits")}
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
	priv.Decode(prik)
	pub := schnorrkel.PublicKey{}
	pub.Decode(pubk)

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

func queryMiners(c *Context, req []byte, method string, miner_uid *int) (ResponseInfo, error) {
	// Query miners with llm request
	var requestBody RequestBody
	err := json.Unmarshal(req, &requestBody)
	if err != nil {
		c.log.Errorf("Error unmarshaling request body: %s\nBody: %s\n", err.Error(), string(req))
		return ResponseInfo{}, errors.New("invalid body")
	}

	// First we get our miners
	miners := getMinersForModel(c, requestBody.Model)
	if len(miners) == 0 {
		return ResponseInfo{}, errors.New("no miners")
	}

	// Call specific miner if passed
	miner := miners[0]
	if miner_uid != nil {
		c.log.Infof("Attempting to find miner %d", *miner_uid)
		found := false
		for i := range miners {
			m := miners[i]
			if m.Uid == *miner_uid {
				miner = m
				found = true
				break
			}
		}
		if !found {
			return ResponseInfo{}, errors.New("no miners")
		}
		c.log.Infof("Requesting Specific miner uid %d", miner.Uid)
	}

	tr := &http.Transport{
		Dial: (&net.Dialer{
			Timeout: 2 * time.Second,
		}).Dial,
		TLSHandshakeTimeout: 2 * time.Second,
		DisableKeepAlives:   false,
	}
	httpClient := http.Client{Transport: tr, Timeout: 2 * time.Minute}

	// query each miner at the same time with the variable context of the
	// parent function via go routines
	tokens := 0

	var imageResponse Image
	var llmResponse []map[string]interface{}
	var timeToFirstToken int64

	route, ok := ROUTES[method]
	if !ok {
		return ResponseInfo{}, errors.New("unknown method")
	}

	endpoint := "http://" + miner.Ip + ":" + fmt.Sprint(miner.Port) + route
	timestamp := time.Now().UnixMilli()
	id := uuid.New().String()
	timestampInterval := int64(math.Ceil(float64(timestamp) / 1e4))

	// Build the rest of the body hash
	bodyHash := sha256Hash(req)
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
	if method == ENDPOINTS.COMPLETION || method == ENDPOINTS.CHAT {
		headers["Connection"] = "keep-alive"
	}

	r, err := http.NewRequest("POST", endpoint, bytes.NewBuffer(req))
	if err != nil {
		c.log.Warnf("Failed miner request: %s\n", err.Error())
		return ResponseInfo{Miner: miner, Success: false}, nil
	}

	// Set headers
	for key, value := range headers {
		r.Header.Set(key, value)
	}
	r.Close = true
	r = r.WithContext(c.Request().Context())

	ctx, cancel := context.WithCancel(c.Request().Context())
	timer := time.AfterFunc(4*time.Second, func() {
		cancel()
	})

	// wrap this line in conditional for chat or completion
	if method == ENDPOINTS.COMPLETION || method == ENDPOINTS.CHAT {
		r = r.WithContext(ctx)
	}

	res, err := httpClient.Do(r)
	start := time.Now()
	if err != nil {
		c.log.Warnf("Miner: %s %s\nError: %s\n", miner.Hotkey, miner.Coldkey, err.Error())
		if res != nil {
			res.Body.Close()
		}
		return ResponseInfo{Miner: miner, Success: false}, nil
	}
	if res.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(res.Body)
		res.Body.Close()
		c.log.Warnf("Miner: %s %s\nError: %s\n", miner.Hotkey, miner.Coldkey, string(body))
		return ResponseInfo{Miner: miner, Success: false}, nil
	}

	c.log.Infof("Miner: %s %s\n", miner.Hotkey, miner.Coldkey)

	switch method {
	case ENDPOINTS.COMPLETION:
		fallthrough
	case ENDPOINTS.CHAT:
		reader := bufio.NewScanner(res.Body)
		finished := false
		for reader.Scan() {
			select {
			case <-c.Request().Context().Done():
				return ResponseInfo{}, errors.New("request canceled")
			default:
				timer.Reset(2 * time.Second)
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
			if method == ENDPOINTS.CHAT {
				return ResponseInfo{Miner: miner, Data: Data{Chat: Chat{ResponseTokens: tokens, TimeToFirstToken: timeToFirstToken, Responses: llmResponse}}, Success: false, Type: ENDPOINTS.CHAT}, nil
			}
			return ResponseInfo{Miner: miner, Data: Data{Completion: Completion{ResponseTokens: tokens, TimeToFirstToken: timeToFirstToken, Responses: llmResponse}}, Success: false, Type: ENDPOINTS.COMPLETION}, nil
		}
	case ENDPOINTS.IMAGE:
		responseBytes, err := io.ReadAll(res.Body)
		if err != nil {
			c.log.Errorf("Failed to read image response: %s", err.Error())
			return ResponseInfo{Miner: miner, Success: false, Type: ENDPOINTS.IMAGE}, nil
		}

		json.Unmarshal(responseBytes, &imageResponse)
		res.Body.Close()
	default:
		return ResponseInfo{}, errors.New("unknown method")
	}

	totalTime := int64(time.Since(start) / time.Millisecond)
	c.log.Infof("Finished Request in %dms", totalTime)

	switch method {
	case ENDPOINTS.IMAGE:
		return ResponseInfo{
			Miner:     miner,
			Success:   true,
			TotalTime: totalTime,

			Type: ENDPOINTS.IMAGE,
			Data: Data{Image: imageResponse},
		}, nil
	case ENDPOINTS.CHAT:
		return ResponseInfo{
			Miner:     miner,
			Success:   true,
			TotalTime: totalTime,

			Type: ENDPOINTS.CHAT,
			Data: Data{Chat: Chat{Responses: llmResponse, ResponseTokens: tokens, TimeToFirstToken: timeToFirstToken}},
		}, nil
	case ENDPOINTS.COMPLETION:
		return ResponseInfo{
			Miner:     miner,
			Success:   true,
			TotalTime: totalTime,

			Type: ENDPOINTS.COMPLETION,
			Data: Data{Completion: Completion{Responses: llmResponse, ResponseTokens: tokens, TimeToFirstToken: timeToFirstToken}},
		}, nil
	default:
		return ResponseInfo{}, errors.New("unknown method")
	}
}

func saveRequest(db *sql.DB, res ResponseInfo, req RequestInfo, logger *zap.SugaredLogger) {
	var (
		model_id int
		cpt      int
	)
	var bodyJson map[string]interface{}
	json.Unmarshal(req.Body, &bodyJson)
	model, ok := bodyJson["model"]
	if !ok {
		logger.Error("No model in body")
		return
	}
	err := db.QueryRow("SELECT id, cpt FROM model WHERE name = ?", model.(string)).Scan(&model_id, &cpt)
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
		VALUES	(?,      ?,       ?,            ?,       ?,        ?,        ?,   ?,      ?,       ?,             ?,        ?,       ?,                  ?,          ?)`,
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

func NewNullString(s string) sql.NullString {
	if len(s) == 0 {
		return sql.NullString{}
	}
	return sql.NullString{
		String: s,
		Valid:  true,
	}
}
