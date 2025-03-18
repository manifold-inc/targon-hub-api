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
	"math/rand"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"
	"sort"
	"api/internal/ratelimit"
	"api/internal/shared"

	"github.com/google/uuid"
	"github.com/gorilla/websocket"
	"github.com/jmcvetta/randutil"
	"github.com/labstack/echo/v4"
	"github.com/nitishm/go-rejson/v4"
	"github.com/redis/go-redis/v9"
	"go.uber.org/zap"
)

type LiveChoices struct {
	mu      sync.Mutex
	Choices []randutil.Choice
}

type ChoiceWithJson struct {
	Weight int `json:"weight"`
	Uid    int `json:"uid"`
}

var liveChoices = LiveChoices{}

func LiveReportWeights(ws *websocket.Conn, c echo.Context) error {
	for {
		if liveChoices.Choices == nil {
			time.Sleep(1 * time.Second)
			continue
		}
		liveChoices.mu.Lock()
		array := [256]ChoiceWithJson{}
		for i := range liveChoices.Choices {
			uid := liveChoices.Choices[i].Item.(shared.Miner).Uid
			array[uid] = ChoiceWithJson{
				Weight: liveChoices.Choices[i].Weight,
				Uid:    uid,
			}
		}
		res, _ := json.Marshal(array)
		liveChoices.mu.Unlock()
		ws.WriteMessage(websocket.TextMessage, res)
		time.Sleep(1 * time.Second)
	}
}

type MinersForModel struct {
	mu          sync.Mutex
	miners      *[]shared.Miner
	lastUpdated time.Time
}

type MinerMap struct {
	mu   sync.Mutex
	mmap map[string]*MinersForModel
}

type MinerSuccessRates struct {
	mu                  sync.Mutex
	Completed           int       `json:"completed"`
	CompletedOverTime   []int     `json:"completedOverTime"`
	Attempted           int       `json:"attempted"`
	Partial             int       `json:"partial"`
	InFlight            int       `json:"inFlight"`
	SuccessRateOverTime []float32 `json:"successRateOverTime"`
	AvgSuccessRate      float32   `json:"avgSuccessRate"`
	LastReset           time.Time `json:"lastReset"`,
	BottomTenTPS        float32   `json:"bottomTenTPS"`
	AvgVerifiedRate     float32   `json:"avgVerifiedRate"`
}

type GlobalStats struct {
	mu                sync.Mutex
	AttemptedOverTime []int
	AttemptedCurrent  int
}

var globalStats = GlobalStats{AttemptedOverTime: []int{}, AttemptedCurrent: 0}

var minerSuccessRatesMap = make(map[int]*MinerSuccessRates)

func InitMiners() {
	for i := 0; i <= 256; i++ {
		minerSuccessRatesMap[i] = &MinerSuccessRates{
			SuccessRateOverTime: []float32{},
			CompletedOverTime:   []int{},
			AvgSuccessRate:      1,
			LastReset:           time.Now(),
			AvgVerifiedRate:     1
		}
	}
}

var minerModelsMap = MinerMap{mmap: make(map[string]*MinersForModel)}

type JugoPayload struct {
	Uid  int            `json:"uid"`
	Data JugoApiPayload `json:"data"`
}
type JugoApiPayload struct {
	Api any `json:"api"`
}

func fetchOrganicStats(public string, private string, hotkey string, logger *zap.SugaredLogger, debug bool) {
	if debug {
		logger.Warn("skipping organic stats fetch since debug")
		return
	}

	endpoint := "https://jugo.targon.com/organic-stats"
	
	r, err := http.NewRequest("GET", endpoint, nil)
	if err != nil {
		logger.Errorw("Failed creating uid stats request", "error", err)
		return
	}

	timestamp := time.Now().UnixMilli()
	id := uuid.New().String()

	bodyHash := sha256Hash([]byte{})
	message := fmt.Sprintf("%s.%s.%d.%s", bodyHash, id, timestamp, "")
	requestSignature := signMessage([]byte(message), public, private)

	headers := map[string]string{
		"Epistula-Version":           "2",
		"Epistula-Timestamp":         fmt.Sprintf("%d", timestamp),
		"Epistula-Uuid":              id,
		"Epistula-Signed-By":         hotkey,
		"Epistula-Request-Signature": requestSignature,
		"Content-Type":               "application/json",
	}
	
	for key, value := range headers {
		r.Header.Set(key, value)
	}
	
	r.Close = true
	httpClient := http.Client{Timeout: 30 * time.Second}
	
	res, err := httpClient.Do(r)
	if err != nil {
		logger.Errorw("Failed fetching organic stats", "error", err)
		return
	}
	defer res.Body.Close()
	
	if res.StatusCode != 200 {
		logger.Errorw("Failed fetching organic stats", "status", res.StatusCode)
		return
	}

	body, err := io.ReadAll(res.Body)
	if err != nil {
		logger.Errorw("Failed reading organic stats response", "error", err)
		return
	}

	var statsResponse map[string]map[string]interface{}
	err = json.Unmarshal(body, &statsResponse)
	if err != nil {
		logger.Errorw("Failed unmarshaling organic stats", "error", err)
		return
	}

	for uidStr, stats := range statsResponse {
		uid, err := strconv.Atoi(uidStr)
		if err != nil {
			logger.Warnw("Invalid UID in organic response", "uid", uidStr)
			continue
		}

		if uid < 0 || uid > 255 {
			continue
		}

		if msrm, ok := minerSuccessRatesMap[uid]; ok {
			msrm.mu.Lock()
			
			if verifiedPct, ok := stats["verified_percentage"].(float64); ok {
				msrm.AvgVerifiedRate = float32(verifiedPct / 100.0)
			}

			// Calculate bottom 10% TPS if we have TPS values
			if tpsValues, ok := stats["tps_values"].([]interface{}); ok && len(tpsValues) > 0 {
				tpsFloats := make([]float32, 0, len(tpsValues))
				for _, v := range tpsValues {
					if f, ok := v.(float64); ok {
						tpsFloats = append(tpsFloats, float32(f))
					}
				}

				if len(tpsFloats) > 0 {
					// Sort TPS values
					sort.Slice(tpsFloats, func(i, j int) bool {
						return tpsFloats[i] < tpsFloats[j]
					})

					// Calculate the bottom 10% mark
					bottomIndex := max(len(tpsFloats)/10, 1)
					if bottomIndex > 0 && bottomIndex <= len(tpsFloats) {
						msrm.BottomTenTPS = tpsFloats[bottomIndex-1]
					}
				}
			}
			
			msrm.mu.Unlock()
		}
	}

	logger.Info("Successfully updated miner verified rates and TPS stats")
}

func ReportStats(public string, private string, hotkey string, logger *zap.SugaredLogger, reset bool, debug bool) {
	var data []JugoPayload
	for k, v := range minerSuccessRatesMap {
		data = append(data, JugoPayload{Data: JugoApiPayload{Api: v}, Uid: k})
	}
	totalAttempted := 0
	for i := range globalStats.AttemptedOverTime {
		totalAttempted += globalStats.AttemptedOverTime[i]
	}

	// -1 is our global registry
	data = append(data, JugoPayload{Uid: -1, Data: JugoApiPayload{Api: map[string]any{
		"totalAttemptedWindow": totalAttempted,
	}}})

	if reset {
		fetchOrganicStats(public, private, hotkey, logger, debug)
		
		// Total attempted window is the same as success rate
		globalStats.mu.Lock()
		globalStats.AttemptedOverTime = append(globalStats.AttemptedOverTime, globalStats.AttemptedCurrent)
		if len(globalStats.AttemptedOverTime) > 10 {
			globalStats.AttemptedOverTime = globalStats.AttemptedOverTime[1:]
		}
		globalStats.AttemptedCurrent = 0
		globalStats.mu.Unlock()

		for _, v := range minerSuccessRatesMap {
			v.mu.Lock()
			rate := float32(1)
			if v.Attempted > 0 && v.Attempted > v.InFlight {
				rate = min(float32(v.Completed)/float32(v.Attempted-v.InFlight), 1)
			}
			v.SuccessRateOverTime = append(v.SuccessRateOverTime, rate)
			if len(v.SuccessRateOverTime) > 10 {
				v.SuccessRateOverTime = v.SuccessRateOverTime[1:]
			}
			v.AvgSuccessRate = min(avgOrOne(v.SuccessRateOverTime), 1)

			v.CompletedOverTime = append(v.CompletedOverTime, v.Completed)
			if len(v.CompletedOverTime) > 10 {
				v.CompletedOverTime = v.CompletedOverTime[1:]
			}

			v.Completed = 0
			v.Attempted = v.InFlight
			v.Partial = 0
			v.LastReset = time.Now()
			v.mu.Unlock()
		}
	}

	if debug {
		logger.Warn("skipping jugo post since debug")
		return
	}

	endpoint := "https://jugo.targon.com/mongo"
	body, err := json.Marshal(data)
	if err != nil {
		logger.Errorw("failed encoding jugo json", "error", err)
		return
	}

	r, _ := http.NewRequest("POST", endpoint, bytes.NewBuffer(body))

	// start creation of signature
	timestamp := time.Now().UnixMilli()
	id := uuid.New().String()

	// Build the rest of the body hash
	bodyHash := sha256Hash(body)
	message := fmt.Sprintf("%s.%s.%d.%s", bodyHash, id, timestamp, "")
	requestSignature := signMessage([]byte(message), public, private)

	headers := map[string]string{
		"Epistula-Version":           "2",
		"Epistula-Timestamp":         fmt.Sprintf("%d", timestamp),
		"Epistula-Uuid":              id,
		"Epistula-Signed-By":         hotkey,
		"Epistula-Request-Signature": requestSignature,
		"Content-Type":               "application/json",
		"X-Targon-Service":           "targon-hub-api",
	}
	headers["Connection"] = "keep-alive"

	// Set headers
	for key, value := range headers {
		r.Header.Set(key, value)
	}
	r.Close = true
	httpClient := http.Client{Timeout: 30 * time.Second}
	res, err := httpClient.Do(r)
	if err != nil {
		logger.Errorw("Failed sending data to jugo", "error", err)
		return
	}
	if res.StatusCode == 200 {
		return
	}
	logger.Errorw("Failed sending data to jugo", "error", res.StatusCode)
}

func getMinersFromRedis(c *shared.Context, model string) (*[]shared.Miner, error) {
	rh := rejson.NewReJSONHandler()
	rh.SetGoRedisClientWithContext(c.Request().Context(), c.Cfg.RedisClient)
	minerJSON, err := rh.JSONGet(model, ".")

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
	return &miners, nil
}

func avgOrOne(arr []float32) float32 {
	length := len(arr)
	if length == 0 {
		return 1
	}
	var sum float32 = 0
	for i := range arr {
		sum += arr[i]
	}
	avg := sum / float32(length)
	return avg
}

func getMinerForModel(c *shared.Context, model string, specific_uid *int) (*shared.Miner, error) {
	// Weighted random based on miner incentive
	minerModelsMap.mu.Lock()
	if _, ok := minerModelsMap.mmap[model]; !ok {
		minerModelsMap.mmap[model] = &MinersForModel{}
		c.Log.Infow("populating miner object from redis")
		miners, err := getMinersFromRedis(c, model)
		if err != nil {
			minerModelsMap.mu.Unlock()
			return nil, err
		}
		minerModelsMap.mmap[model].miners = miners
		minerModelsMap.mmap[model].lastUpdated = time.Now()
	}
	minerModelsMap.mu.Unlock()
	minerModelsMap.mmap[model].mu.Lock()
	if time.Since(minerModelsMap.mmap[model].lastUpdated) > time.Minute*10 {
		c.Log.Infow("updating miner object from redis")
		miners, err := getMinersFromRedis(c, model)
		if err != nil {
			minerModelsMap.mmap[model].mu.Unlock()
			return nil, err
		}
		minerModelsMap.mmap[model].miners = miners
		minerModelsMap.mmap[model].lastUpdated = time.Now()
	}
	miners := *minerModelsMap.mmap[model].miners
	minerModelsMap.mmap[model].mu.Unlock()

	indices := rand.Perm(len(miners))

	var choices []randutil.Choice
	for _, i := range indices {
		if specific_uid != nil && miners[i].Uid == *specific_uid {
			return &miners[i], nil
		}

		// Calculate weight factoring in success rate
		uid := miners[i].Uid

		msrm := minerSuccessRatesMap[uid]
		msrm.mu.Lock()
		successRate := msrm.AvgSuccessRate
		liveSuccessRate := float32(1)

		if msrm.Attempted > 10 {
			liveSuccessRate = float32(msrm.Completed) / float32(max(msrm.Attempted-msrm.InFlight, 1))
		}
		msrm.mu.Unlock()

		// scale so we have room to play with percentages
		weight := miners[i].Weight * 100
		weight = max(int(float32(weight)*successRate*liveSuccessRate), 0)

		// Still need to give these miners a chance to re-gain trust, so cant fully zero
		if successRate < .50 || liveSuccessRate < .5 {
			weight = 1
		}

		// softcap weight for those with unproven success rates
		if weight > 50 && successRate < .9 {
			weight = 50
		}

		ch := randutil.Choice{Item: miners[i], Weight: weight}
		choices = append(choices, ch)
	}
	liveChoices.mu.Lock()
	liveChoices.Choices = choices
	liveChoices.mu.Unlock()
	if specific_uid != nil {
		return nil, errors.New("couldnt find uid %d")
	}
	choice, err := randutil.WeightedChoice(choices)
	if err != nil {
		c.Log.Warnw("Failed getting weighted random choice", "error", err.Error())
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
			return nil, err
		}
		miner = *m
	}
	c.Log = c.Log.With("uid", miner.Uid)

	// Increment mutexes for in memory stats
	m := minerSuccessRatesMap[miner.Uid]
	m.mu.Lock()
	m.Attempted++
	m.InFlight++
	defer func() {
		minerSuccessRatesMap[miner.Uid].mu.Lock()
		minerSuccessRatesMap[miner.Uid].InFlight--
		minerSuccessRatesMap[miner.Uid].mu.Unlock()
	}()
	m.mu.Unlock()
	globalStats.mu.Lock()
	globalStats.AttemptedCurrent++
	globalStats.mu.Unlock()

	tr := &http.Transport{
		Dial: (&net.Dialer{
			Timeout: 2 * time.Second,
		}).Dial,
		TLSHandshakeTimeout: 2 * time.Second,
		DisableKeepAlives:   false,
	}
	httpClient := http.Client{Transport: tr, Timeout: 10 * time.Minute}

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
			fmt.Appendf([]byte{}, "%d.%s", timestampInterval-1, miner.Hotkey),
			c.Cfg.Env.PublicKey,
			c.Cfg.Env.PrivateKey,
		),
		"Epistula-Secret-Signature-1": signMessage(
			fmt.Appendf([]byte{}, "%d.%s", timestampInterval, miner.Hotkey),
			c.Cfg.Env.PublicKey,
			c.Cfg.Env.PrivateKey,
		),
		"Epistula-Secret-Signature-2": signMessage(
			fmt.Appendf([]byte{}, "%d.%s", timestampInterval+1, miner.Hotkey),
			c.Cfg.Env.PublicKey,
			c.Cfg.Env.PrivateKey,
		),
		"X-Targon-Model":      req.Model,
		"Content-Type":        "application/json",
		"X-Targon-Request-Id": c.Reqid,
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
	responseError := "never receieved DONE token"
	r = r.WithContext(ctx)
	timer = time.AfterFunc(8*time.Second, func() {
		responseError = "first token took too long"
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
		return &shared.ResponseInfo{Miner: miner, Success: false, Error: "Failed reading body: " + string(body)}, nil
	}

	c.Log.Infow(
		"Sending organic to miner",
	)
	reader := bufio.NewScanner(res.Body)
	finished := false
	tokens := 0
	var llmResponse []map[string]any
	var timeToFirstToken int64

	for reader.Scan() {
		select {
		case <-c.Request().Context().Done():
			return &shared.ResponseInfo{}, errors.New("request canceled")
		default:
			timer.Stop()
			token := reader.Text()
			if c.Cfg.Env.Debug {
				fmt.Println(token)
			}
			fmt.Fprint(c.Response(), token+"\n\n")
			c.Response().Flush()
			if token == "data: [DONE]" {
				responseError = ""
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
				var response map[string]any
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

	if len(llmResponse) < 2 {
		finished = false
	}

	responseInfo := &shared.ResponseInfo{
		Miner:            miner,
		Success:          finished,
		Type:             shared.ENDPOINTS.CHAT,
		Responses:        llmResponse,
		ResponseTokens:   tokens,
		TimeToFirstToken: timeToFirstToken,
		TotalTime:        totalTime,
		Error:            responseError,
	}
	if !finished {
		select {
		// If user cancelled request, we remove it from the attempted
		case <-c.Request().Context().Done():
			// Track cancellation for behavior monitoring
			ratelimit.TrackCancellation(context.Background(), c.Cfg.RedisClient, req.UserId, c.Log)

			c.Log.Warnw("Request canceled by client",
				"user_id", req.UserId)

			minerSuccessRatesMap[miner.Uid].mu.Lock()
			minerSuccessRatesMap[miner.Uid].Attempted = max(minerSuccessRatesMap[miner.Uid].Attempted-1, 0)
			minerSuccessRatesMap[miner.Uid].mu.Unlock()
			responseInfo.Error = "user canceled request"
			return responseInfo, nil
		default:
			break
		}
		minerSuccessRatesMap[miner.Uid].mu.Lock()
		minerSuccessRatesMap[miner.Uid].Partial++
		minerSuccessRatesMap[miner.Uid].mu.Unlock()
		responseInfo.Error = "Premature end of generation"
		return responseInfo, nil
	}
	c.Log.Infow(
		"Finished Request",
		"final", "true",
		"status", "success",
		"duration", fmt.Sprintf("%d", time.Since(req.StartTime)/time.Millisecond),
		"tokens", tokens,
	)
	minerSuccessRatesMap[miner.Uid].mu.Lock()
	minerSuccessRatesMap[miner.Uid].Completed++
	minerSuccessRatesMap[miner.Uid].mu.Unlock()
	return responseInfo, nil
}
