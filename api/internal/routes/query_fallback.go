package routes

import (
	"bufio"
	"bytes"
	"database/sql"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"time"

	"api/internal/shared"
)

func QueryFallback(c *shared.Context, req *shared.RequestInfo) *shared.RequestError {
	// Get Fallback Server
	var fallback_server string
	err := c.Cfg.SqlClient.QueryRow("SELECT model.fallback_server FROM model WHERE model.name = ?", req.Model).
		Scan(&fallback_server)
	if err == sql.ErrNoRows && !c.Cfg.Env.Debug {
		return &shared.RequestError{StatusCode: 400, Err: fmt.Errorf("no model found for %s", req.Model)}
	}
	if err != nil {
		return &shared.RequestError{StatusCode: 500, Err: errors.New("internal server error")}
	}

	// Initialize http request
	route := shared.ROUTES[req.Endpoint]
	r, err := http.NewRequest("POST", fallback_server+route, bytes.NewBuffer(req.Body))
	if err != nil {
		c.Log.Warnw("Failed building fallback request", "error", err.Error())
	}

	// Create headers for connecting to fallback
	headers := map[string]string{
		"X-Targon-Model": req.Model,
		"Authorization":  fmt.Sprintf("Bearer %s", c.Cfg.Env.FallbackApiKey),
		"Content-Type":   "application/json",
		"Connection":     "keep-alive",
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

	// Start Request
	res, err := httpClient.Do(r)
	if res != nil {
		defer res.Body.Close()
	}
	if err != nil {
		c.Log.Warnw("Fallback request failed", "error", err)
		return &shared.RequestError{StatusCode: 429, Err: errors.New("fallback request failed")}
	}
	if res.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(res.Body)
		res.Body.Close()
		c.Log.Warnw("Fallback request failed", "error", body)
		return &shared.RequestError{StatusCode: 429, Err: errors.New("fallback request failed")}
	}
	reader := bufio.NewScanner(res.Body)

	// Stream back response
	tokens := 0
scanner:
	for reader.Scan() {
		select {
		case <-c.Request().Context().Done():
			return &shared.RequestError{StatusCode: 400, Err: errors.New("request canceled")}
		default:
			token := reader.Text()
			fmt.Fprint(c.Response(), token+"\n\n")
			c.Response().Flush()
			if token == "data: [DONE]" {
				break scanner
			}
			if _, found := strings.CutPrefix(token, "data: "); found {
				if tokens == 0 {
					c.Log.Infow("time to first token", "duration", fmt.Sprintf("%d", time.Since(req.StartTime)/time.Millisecond), "from", "fallback")
				}
				tokens += 1
			}
		}
	}
	c.Log.Infow(
		"Finished fallback request",
		"final", "true",
		"status", "success",
		"duration", fmt.Sprintf("%d", time.Since(req.StartTime)/time.Millisecond),
		"tokens", tokens,
	)
	return nil
}
