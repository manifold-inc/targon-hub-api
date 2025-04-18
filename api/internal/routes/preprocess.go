package routes

import (
	"database/sql"
	"encoding/json"
	"errors"
	"io"
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

	// Get and validate bearer token
	bearer := c.Request().Header.Get("Authorization")
	if bearer == "" {
		c.Log.Warn("Missing Authorization header")
		return nil, &shared.RequestError{StatusCode: 401, Err: errors.New("unauthorized")}
	}

	// Validate token format
	parts := strings.Split(bearer, " ")
	if len(parts) < 2 || strings.ToLower(parts[0]) != "bearer" {
		c.Log.Warnw("Malformed bearer token", "token", bearer)
		return nil, &shared.RequestError{StatusCode: 401, Err: errors.New("invalid authentication")}
	}

	apiKey := parts[1]

	if len(apiKey) != 32 {
		c.Log.Warnw("Invalid API key length", "length", len(apiKey))
		return nil, &shared.RequestError{StatusCode: 401, Err: errors.New("invalid authentication")}
	}

	// Get user object
	var (
		credits    int64
		userid     int
		chargeable bool
	)
	err := c.Cfg.ReadSqlClient.QueryRow("SELECT user.credits, user.id, user.chargeable FROM user INNER JOIN api_key ON user.id = api_key.user_id WHERE api_key.id = ?", apiKey).
		Scan(&credits, &userid, &chargeable)
	if err == sql.ErrNoRows && !c.Cfg.Env.Debug {
		c.Log.Warnf("no user found for bearer token %s", bearer)
		return nil, &shared.RequestError{StatusCode: 401, Err: errors.New("unauthorized")}
	}
	if err != nil && !c.Cfg.Env.Debug {
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
				"Malformed request",
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

	if _, ok := payload["max_tokens"]; !ok {
		payload["max_tokens"] = 512
	}

	// Repackage body
	body, err = json.Marshal(payload)
	if err != nil {
		c.Log.Errorw("Failed re-marshaling request", "error", err.Error())
		return nil, &shared.RequestError{StatusCode: 500, Err: errors.New("internal server error")}
	}
	res := &shared.RequestInfo{Body: body, UserId: userid, StartingCredits: credits, Id: c.Reqid, Chargeable: chargeable, StartTime: startTime, Endpoint: endpoint, Model: model.(string)}
	return res, nil
}
