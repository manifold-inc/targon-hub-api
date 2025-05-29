package routes

import (
	"bufio"
	"bytes"
	"context"
	"database/sql"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"time"

	"api/internal/ratelimit"
	"api/internal/shared"
)

func QueryModels(c *shared.Context, req *shared.RequestInfo) (*shared.ResponseInfo, *shared.RequestError) {
	// Get Fallback Server
	var fallback_server string
	err := c.Cfg.ReadSqlClient.QueryRow("SELECT model.fallback_server FROM model WHERE model.name = ?", req.Model).
		Scan(&fallback_server)
	if err == sql.ErrNoRows && !c.Cfg.Env.Debug {
		return nil, &shared.RequestError{StatusCode: 400, Err: fmt.Errorf("no model found for %s", req.Model)}
	}
	if err != nil {
		return nil, &shared.RequestError{StatusCode: 500, Err: errors.New("internal server error")}
	}

	// Initialize http request
	route := shared.ROUTES[req.Endpoint]
	r, err := http.NewRequest("POST", fallback_server+route, bytes.NewBuffer(req.Body))
	if err != nil {
		c.Log.Warnw("Failed building fallback request", "error", err.Error())
	}

	// Create headers for connecting to fallback
	headers := map[string]string{
		"X-Targon-Model":       req.Model,
		"Authorization":        fmt.Sprintf("Bearer %s", c.Cfg.Env.FallbackApiKey),
		"Content-Type":         "application/json",
		"Connection":           "keep-alive",
		"X-Targon-Request-Id":  c.Reqid,
		"X-Targon-External-Id": c.ExternalId,
	}

	// Set headers
	for key, value := range headers {
		r.Header.Set(key, value)
	}
	r.Close = true
	r = r.WithContext(c.Request().Context())
	tr := &http.Transport{
		Dial: (&net.Dialer{
			Timeout: 10 * time.Second,
		}).Dial,
		TLSHandshakeTimeout: 5 * time.Second,
		DisableKeepAlives:   false,
	}
	httpClient := http.Client{Transport: tr, Timeout: 10 * time.Minute}

	// Start Request
	res, err := httpClient.Do(r)
	if err != nil {
		c.Log.Warnw("Fallback request failed", "error", err)
		return nil, &shared.RequestError{StatusCode: 429, Err: errors.New("fallback request failed")}
	}
	defer func() {
		_ = res.Body.Close()
	}()
	if res.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(res.Body)
		c.Log.Warnw("Fallback request failed", "error", body)
		return nil, &shared.RequestError{StatusCode: 429, Err: errors.New("fallback request failed")}
	}
	reader := bufio.NewScanner(res.Body)

	// Stream back response
	tokens := 0
	var ttft int32
	var responseBuilder strings.Builder
scanner:
	for reader.Scan() {
		select {
		case <-c.Request().Context().Done():
			// Track cancellation in fallback route
			ratelimit.TrackCancellation(context.Background(), c.Cfg.RedisClient, req.UserId, c.Log)

			c.Log.Warnw("Request canceled by client during fallback",
				"user_id", req.UserId)

			return nil, &shared.RequestError{StatusCode: 400, Err: errors.New("request canceled")}
		default:
			token := reader.Text()
			responseBuilder.WriteString(token)
			responseBuilder.WriteString("\n\n")
			_, _ = fmt.Fprint(c.Response(), token+"\n\n")
			c.Response().Flush()
			if token == "data: [DONE]" {
				c.Log.Infow("Inference engine returned [DONE]", "final", "true", "status", "success", "reqID", req.Id, "model", req.Model)
				break scanner
			}
			if _, found := strings.CutPrefix(token, "data: "); found {
				if tokens == 0 {
					ttft = int32(time.Since(req.StartTime))
					c.Log.Infow("time to first token", "duration", fmt.Sprintf("%d", time.Since(req.StartTime)/time.Millisecond), "from", "fallback")
				}
				tokens += 1
			}
		}
	}
	completeResponse := responseBuilder.String()
	if req.UserId != 64 {
		completeResponse = ""
	}
	c.Log.Infow(
		"Finished fallback request",
		"final", "true",
		"status", "success",
		"duration", fmt.Sprintf("%d", time.Since(req.StartTime)/time.Millisecond),
		"tokens", tokens,
	)
	resInfo := shared.ResponseInfo{
		TotalTime:            int32(time.Since(req.StartTime)),
		ResponseTokens:       tokens,
		TimeToFirstToken:     ttft,
		ResponseTokensString: completeResponse,
	}
	return &resInfo, nil
}
