package routes

import (
	"database/sql"
	"encoding/json"
	"errors"
	"io"
	"math/rand"
	"strconv"
	"strings"
	"time"

	"api/internal/shared"
)

func preprocessOpenaiRequest(
	c *shared.Context,
	endpoint string,
) (*shared.RequestInfo, *shared.RequestError) {
	// Set response Headers
	startTime := time.Now()
	c.Log = c.Log.With("endpoint", endpoint)
	c.Response().Header().Set("Cache-Control", "no-cache")
	c.Response().Header().Set("Connection", "keep-alive")
	c.Response().Header().Set("X-Accel-Buffering", "no")
	c.Response().Header().Set("Content-Type", "text/event-stream; charset=utf-8")
	c.Request().Header.Add("Content-Type", "application/json")
	bearer := c.Request().Header.Get("Authorization")

	// Get user object
	var (
		credits    int64
		userid     int
		chargeable bool
	)
	err := c.Cfg.SqlClient.QueryRow("SELECT user.credits, user.id, user.chargeable FROM user INNER JOIN api_key ON user.id = api_key.user_id WHERE api_key.id = ?", strings.Split(bearer, " ")[1]).
		Scan(&credits, &userid, &chargeable)
	if err == sql.ErrNoRows && !c.Cfg.Env.Debug {
		c.Log.Warnf("no user found for bearer token %s", bearer)
		return nil, &shared.RequestError{StatusCode: 401, Err: errors.New("unauthorized")}
	}
	if err != nil {
		c.Log.Errorw("Error fetching user data from api key", "error", err)
		return nil, &shared.RequestError{StatusCode: 500, Err: errors.New("internal server error")}
	}

	// add user id to future logs
	c.Log = c.Log.With("user_id", userid)

	body, _ := io.ReadAll(c.Request().Body)
	// Ensure properly formatted request
	var req shared.Request
	err = json.Unmarshal(body, &req)
	if err != nil {
		return nil, &shared.RequestError{
			StatusCode: 400,
			Err: errors.New(
				"targon only supports basic chat requests with `role:string` and `content:string`",
			),
		}
	}

	// Unmarshal to generic map to set defaults
	var payload map[string]any
	err = json.Unmarshal(body, &payload)
	if err != nil {
		c.Log.Warnw("failed json unmarshall", "error", err.Error())
		return nil, &shared.RequestError{StatusCode: 500, Err: errors.New("internal server error")}
	}

	// Get Model
	model, ok := payload["model"]
	if !ok {
		c.Log.Warn("No model in request body")
		return nil, &shared.RequestError{StatusCode: 500, Err: errors.New("model field required")}
	}
	c.Log = c.Log.With("model", model.(string))

	// Set defaults if need be
	if (req.MaxTokens > uint64(credits) || 512 > uint64(credits)) && chargeable {
		return nil, &shared.RequestError{StatusCode: 400, Err: errors.New("not enough credits")}
	}

	if val, ok := payload["stream"]; !ok || val == nil {
		payload["stream"] = true
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

	// Repackage body
	body, err = json.Marshal(payload)
	if err != nil {
		c.Log.Errorw("Failed re-marshaling request", "error", err.Error())
		return nil, &shared.RequestError{StatusCode: 500, Err: errors.New("internal server error")}
	}

	// Create request info data
	var miner, minerHost string
	res := &shared.RequestInfo{Body: body, UserId: userid, StartingCredits: credits, Id: c.Reqid, Chargeable: chargeable, StartTime: startTime, Endpoint: endpoint, Model: model.(string)}
	if c.Cfg.Env.Debug {
		miner = c.Request().Header.Get("X-Targon-Miner-Uid")
		minerHost = c.Request().Header.Get("X-Targon-Miner-Ip")
	}
	miner_uid, err := strconv.Atoi(miner)
	if err == nil {
		res.Miner = &miner_uid
	}
	res.MinerHost = minerHost

	return res, nil
}
