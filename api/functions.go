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
	"strings"
	"time"

	"github.com/ChainSafe/go-schnorrkel"
	"github.com/aidarkhanov/nanoid"
	"github.com/google/uuid"
	"github.com/nitishm/go-rejson/v4"
)

func preprocessOpenaiRequest(c *Context, db *sql.DB) (*RequestInfo, error) {
	c.Request().Header.Add("Content-Type", "application/json")
	bearer := c.Request().Header.Get("Authorization")
	c.Response().Header().Set("Content-Type", "text/event-stream; charset=utf-8")
	c.Response().Header().Set("Cache-Control", "no-cache")
	c.Response().Header().Set("Connection", "keep-alive")
	c.Response().Header().Set("X-Accel-Buffering", "no")

	var (
		credits int
		userid  int
	)
	err := db.QueryRow("SELECT user.credits, user.id FROM user INNER JOIN api_key ON user.id = api_key.user_id WHERE api_key.id = ?", strings.Split(bearer, " ")[1]).Scan(&credits, &userid)
	if err == sql.ErrNoRows {
		c.Warn.Println(bearer)
		return nil, &RequestError{401, errors.New("Unauthorized")}
	}
	if err != nil {
		c.Err.Println(err)
		sendErrorToEndon(err, "/v1/chat/completions")
		return nil, &RequestError{500, errors.New("Interal Server Error")}
	}
	if credits < 0 {
		return nil, &RequestError{403, errors.New("Out of credits")}
	}
	body, _ := io.ReadAll(c.Request().Body)
	if err != nil {
		c.Err.Println(err)
		return nil, &RequestError{500, errors.New("Internal Server Error")}
	}

	return &RequestInfo{Body: body, UserId: userid, StartingCredits: credits}, nil
}

func safeEnv(env string) string {
	// Lookup env variable, and panic if not present

	res, present := os.LookupEnv(env)
	if !present {
		log.Fatalf("Missing environment variable %s", env)
	}
	return res
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
		c.Err.Printf("Failed to JSONGet: %s\n", err.Error())
		return nil
	}

	var miners []Miner
	err = json.Unmarshal(minerJSON.([]byte), &miners)
	if err != nil {
		c.Err.Printf("Failed to JSON Unmarshal: %s\n", err.Error())
		return nil
	}
	for i := range miners {
		j := rand.Intn(i + 1)
		miners[i], miners[j] = miners[j], miners[i]
	}
	return miners
}

func queryMiners(c *Context, req []byte, method string) (ResponseInfo, error) {
	// Query miners with llm request
	var requestBody RequestBody
	err := json.Unmarshal(req, &requestBody)
	if err != nil {
		c.Err.Printf("Error unmarshaling request body: %s\nBody: %s\n", err.Error(), string(req))
		return ResponseInfo{}, errors.New("Invalid Body")
	}

	// First we get our miners
	miners := getMinersForModel(c, requestBody.Model)
	if miners == nil || len(miners) == 0 {
		return ResponseInfo{}, errors.New("No Miners")
	}
	miner := miners[0]

	// Build the rest of the body hash
	tr := &http.Transport{
		Dial: (&net.Dialer{
			Timeout: 2 * time.Second,
		}).Dial,
		TLSHandshakeTimeout:   2 * time.Second,
		ResponseHeaderTimeout: 4 * time.Second,
		DisableKeepAlives:     false,
	}
	httpClient := http.Client{Transport: tr, Timeout: 10 * time.Second}

	// query each miner at the same time with the variable context of the
	// parent function via go routines
	tokens := 0
	endpoint := "http://" + miner.Ip + ":" + fmt.Sprint(miner.Port) + method
	timestamp := time.Now().UnixMilli()
	id := uuid.New().String()
	timestampInterval := int64(math.Ceil(float64(timestamp) / 1e4))

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
		"Connection":                  "keep-alive",
	}

	ctx, cancel := context.WithCancel(c.Request().Context())
	timer := time.AfterFunc(4*time.Second, func() {
		cancel()
	})
	r, err := http.NewRequest("POST", endpoint, bytes.NewBuffer(req))
	if err != nil {
		c.Warn.Printf("Failed miner request: %s\n", err.Error())
		return ResponseInfo{Miner: miner, Tokens: tokens, Responses: nil, Success: false}, nil
	}

	// Set headers
	for key, value := range headers {
		r.Header.Set(key, value)
	}
	r.Close = true
	r.WithContext(c.Request().Context())

	r = r.WithContext(ctx)
	res, err := httpClient.Do(r)
	if err != nil {
		c.Warn.Printf("Miner: %s %s\nError: %s\n", miner.Hotkey, miner.Coldkey, err.Error())
		if res != nil {
			res.Body.Close()
		}
		return ResponseInfo{Miner: miner, Tokens: tokens, Responses: nil, Success: false}, nil
	}
	if res.StatusCode != http.StatusOK {
		bdy, _ := io.ReadAll(res.Body)
		res.Body.Close()
		c.Warn.Printf("Miner: %s %s\nError: %s\n", miner.Hotkey, miner.Coldkey, string(bdy))
		return ResponseInfo{Miner: miner, Tokens: tokens, Responses: nil, Success: false}, nil
	}

	c.Info.Printf("Miner: %s %s\n", miner.Hotkey, miner.Coldkey)
	reader := bufio.NewScanner(res.Body)
	finished := false
	var responses []map[string]interface{}
	for reader.Scan() {
		select {
		case <-c.Request().Context().Done():
			return ResponseInfo{}, errors.New("Request Canceled")
		default:
			timer.Reset(2 * time.Second)
			token := reader.Text()
			fmt.Fprintf(c.Response(), token+"\n\n")
			c.Response().Flush()
			if token == "data: [DONE]" {
				finished = true
				break
			}
			token, found := strings.CutPrefix(token, "data: ")
			if found {
				tokens += 1
				var response map[string]interface{}
				err := json.Unmarshal([]byte(token), &response)
				if err != nil {
					c.Err.Printf("Failed decoing token string: %s", err)
					continue
				}
				responses = append(responses, response)
			}
		}
	}
	res.Body.Close()
	if finished == false {
		return ResponseInfo{Miner: miner, Tokens: tokens, Responses: responses, Success: false}, nil
	}
	return ResponseInfo{Miner: miner, Tokens: tokens, Responses: responses, Success: true}, nil
}

func saveRequest(db *sql.DB, res ResponseInfo, req RequestInfo, logger *log.Logger) {
	var (
		model_id int
		cpt      int
	)
	var bodyJson map[string]interface{}
	json.Unmarshal(req.Body, &bodyJson)
	model, ok := bodyJson["model"]
	if !ok {
		logger.Println("No model in body")
		return
	}
	err := db.QueryRow("SELECT id, cpt FROM model WHERE name = ?", model.(string)).Scan(&model_id, &cpt)
	if err != nil {
		logger.Println("Failed to get model")
		logger.Println(err)
		return
	}
	_, err = db.Exec("UPDATE user SET credits=? WHERE id=?",
		req.StartingCredits-(res.Tokens*cpt),
		req.UserId)
	if err != nil {
		logger.Println("Failed to update")
		logger.Println(err)
	}

	responseJson, _ := json.Marshal(res.Responses)
	pubId, _ := nanoid.Generate("0123456789abcdefghijklmnopqrstuvwxyz", 28)
	pubId = "req_" + pubId
	_, err = db.Exec(`
	INSERT INTO 
		request (pub_id, user_id, credits_used, tokens, request, response, model_id, uid, hotkey, coldkey, miner_address, endpoint, success) 
		VALUES	(?,      ?,       ?,            ?,      ?,       ?,        ?,        ?,   ?,      ?,       ?,             ?,        ?)`,
		pubId,
		req.UserId,
		res.Tokens*cpt,
		res.Tokens,
		string(req.Body),
		string(responseJson),
		model_id,
		res.Miner.Uid,
		res.Miner.Hotkey,
		res.Miner.Coldkey,
		fmt.Sprintf("http://%s:%d",
			res.Miner.Ip,
			res.Miner.Port),
		req.Endpoint,
		res.Success,
	)

	if err != nil {
		logger.Println("Failed to update")
		logger.Println(err)
		return
	}
	return
}

func sendErrorToEndon(err error, endpoint string) {
	payload := ErrorReport{
		Service:  "targon-hub-api",
		Endpoint: endpoint,
		Error:    err.Error(),
	}

	jsonData, jsonErr := json.Marshal(payload)
	if jsonErr != nil {
		log.Printf("Failed to marshal error payload: %v\n", jsonErr)
		return
	}

	client := &http.Client{Timeout: 10 * time.Second}
	req, reqErr := http.NewRequest(http.MethodPost, ENDON_URL, bytes.NewBuffer(jsonData))
	if reqErr != nil {
		log.Printf("Failed to create Endon request: %v\n", reqErr)
		return
	}

	req.Header.Set("Content-Type", "application/json")

	resp, respErr := client.Do(req)
	if respErr != nil {
		log.Printf("Failed to send error to Endon: %v\n", respErr)
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		log.Printf("Failed to report error to Endon. Status: %d\n", resp.StatusCode)
		return
	}

	fmt.Printf("Successfully sent error to Endon: %s\n", endpoint)
}
