package bittensor

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"

	"api/internal/shared"

	"github.com/google/uuid"
	"github.com/jmcvetta/randutil"
	"github.com/nitishm/go-rejson/v4"
	"github.com/redis/go-redis/v9"
)

func getMinerForModel(c *shared.Context, model string, specific_uid *int) (*shared.Miner, error) {
	// Weighted random based on miner incentive
	rh := rejson.NewReJSONHandler()
	rh.SetGoRedisClientWithContext(c.Request().Context(), c.Cfg.RedisClient)
	minerJSON, err := rh.JSONGet(model, ".")
	var choices []randutil.Choice

	// Model not available
	if err == redis.Nil {
		c.Log.Warnf("No miners running %s", model)
		return nil, errors.New("no miners")
	}
	if err == context.Canceled {
		c.Log.Warn("Request canceled")
		return nil, errors.New("request canceled")
	}
	if err != nil {
		c.Log.Errorw("Failed to get model from redis", "error", err.Error())
		return nil, errors.New("failed to get miners from redis")
	}

	var miners []shared.Miner
	err = json.Unmarshal(minerJSON.([]byte), &miners)
	if err != nil {
		c.Log.Errorw("Failed to JSON Unmarshal", "error", err.Error())
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
		c.Log.Errorw("Failed getting weighted random choice", "error", err.Error())
		return &miners[0], nil
	}
	miner := choice.Item.(shared.Miner)
	return &miner, nil
}

func QueryMiner(c *shared.Context, req *shared.RequestInfo) (*shared.ResponseInfo, error) {
	var miner shared.Miner

	if len(req.MinerHost) != 0 {
		host := strings.TrimPrefix(req.MinerHost, "http://")
		ip := strings.Split(host, ":")[0]
		port, _ := strconv.Atoi(strings.Split(host, ":")[1])
		miner = shared.Miner{
			Ip:      ip,
			Port:    port,
			Hotkey:  "",
			Coldkey: "",
			Uid:     -1,
		}
	}

	// Only get miners from redis if we dont specify host
	if len(req.MinerHost) == 0 {
		m, err := getMinerForModel(c, req.Model, req.Miner)
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
	var llmResponse []map[string]interface{}
	var timeToFirstToken int64

	route, ok := shared.ROUTES[req.Endpoint]
	if !ok {
		return nil, errors.New("unknown method")
	}

	endpoint := "http://" + miner.Ip + ":" + fmt.Sprint(miner.Port) + route

	r, err := http.NewRequest("POST", endpoint, bytes.NewBuffer(req.Body))
	if err != nil {
		return &shared.ResponseInfo{Miner: miner, Success: false, Error: err.Error()}, nil
	}

	// start creation of signature
	timestamp := time.Now().UnixMilli()
	id := uuid.New().String()
	timestampInterval := int64(math.Ceil(float64(timestamp) / 1e4))

	// Build the rest of the body hash
	bodyHash := sha256Hash(req.Body)
	message := fmt.Sprintf("%s.%s.%d.%s", bodyHash, id, timestamp, miner.Hotkey)
	requestSignature := signMessage([]byte(message), c.Cfg.Env.PublicKey, c.Cfg.Env.PrivateKey)

	headers := map[string]string{
		"Epistula-Version":           "2",
		"Epistula-Timestamp":         fmt.Sprintf("%d", timestamp),
		"Epistula-Uuid":              id,
		"Epistula-Signed-By":         c.Cfg.Env.Hotkey,
		"Epistula-Signed-For":        miner.Hotkey,
		"Epistula-Request-Signature": requestSignature,
		"Epistula-Secret-Signature-0": signMessage(
			[]byte(fmt.Sprintf("%d.%s", timestampInterval-1, miner.Hotkey)),
			c.Cfg.Env.PublicKey,
			c.Cfg.Env.PrivateKey,
		),
		"Epistula-Secret-Signature-1": signMessage(
			[]byte(fmt.Sprintf("%d.%s", timestampInterval, miner.Hotkey)),
			c.Cfg.Env.PublicKey,
			c.Cfg.Env.PrivateKey,
		),
		"Epistula-Secret-Signature-2": signMessage(
			[]byte(fmt.Sprintf("%d.%s", timestampInterval+1, miner.Hotkey)),
			c.Cfg.Env.PublicKey,
			c.Cfg.Env.PrivateKey,
		),
		"X-Targon-Model": req.Model,
		"Content-Type":   "application/json",
	}
	headers["Connection"] = "keep-alive"

	// Set headers
	for key, value := range headers {
		r.Header.Set(key, value)
	}
	r.Close = true
	r = r.WithContext(c.Request().Context())

	// Cancel request with user cancelation
	ctx, cancel := context.WithCancel(c.Request().Context())
	defer cancel()
	var timer *time.Timer

	// Cancel with timer
	r = r.WithContext(ctx)
	timer = time.AfterFunc(4*time.Second, func() {
		cancel()
	})

	res, err := httpClient.Do(r)
	start := time.Now()
	if err != nil {
		if res != nil {
			res.Body.Close()
		}
		return &shared.ResponseInfo{Miner: miner, Success: false, Error: err.Error()}, nil
	}
	if res.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(res.Body)
		res.Body.Close()
		return &shared.ResponseInfo{Miner: miner, Success: false, Error: string(body)}, nil
	}

	c.Log.Infow(
		"Sending organic to miner",
		"hotkey",
		miner.Hotkey,
		"coldkey",
		miner.Coldkey,
		"uid",
		miner.Uid,
	)
	reader := bufio.NewScanner(res.Body)
	finished := false
	for reader.Scan() {
		select {
		case <-c.Request().Context().Done():
			return &shared.ResponseInfo{}, errors.New("request canceled")
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
					c.Log.Infow(
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
					c.Log.Warnw(
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
	totalTime := int64(time.Since(start) / time.Millisecond)

	responseInfo := &shared.ResponseInfo{
		Miner:            miner,
		Success:          finished,
		Type:             shared.ENDPOINTS.CHAT,
		Responses:        llmResponse,
		ResponseTokens:   tokens,
		TimeToFirstToken: timeToFirstToken,
		TotalTime:        totalTime,
	}
	if !finished {
		return responseInfo, nil
	}
	c.Log.Infow(
		"Finished Request",
		"final", "true",
		"status", "success",
		"duration", fmt.Sprintf("%d", time.Since(req.StartTime)/time.Millisecond),
		"tokens", tokens,
	)
	return responseInfo, nil
}
