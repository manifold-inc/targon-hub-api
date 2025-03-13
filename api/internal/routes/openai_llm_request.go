package routes

import (
	"fmt"
	"time"

	"api/internal/bittensor"
	"api/internal/database"
	"api/internal/shared"

	"github.com/labstack/echo/v4"
)

func ChatRequest(c echo.Context) error {
	return ProcessOpenaiRequest(c, shared.ENDPOINTS.CHAT)
}

func CompletionRequest(c echo.Context) error {
	return ProcessOpenaiRequest(c, shared.ENDPOINTS.COMPLETION)
}

func ProcessOpenaiRequest(cc echo.Context, endpoint string) error {
	c := cc.(*shared.Context)
	defer func() {
		_ = c.Log.Sync()
	}()
	request, preprocessError := preprocessOpenaiRequest(c, endpoint)
	if preprocessError != nil {
		return c.String(preprocessError.StatusCode, preprocessError.Error())
	}

	res, err := bittensor.QueryMiner(c, request)
	if err != nil {
		c.Log.Warnw(
			"Failed request, most likely un-recoverable. Not sending to fallback",
			"status", "failed",
			"error", err.Error(),
			"final", "true",
		)
		return c.JSON(500, shared.OpenAIError{
			Message: err.Error(),
			Object:  "error",
			Type:    "InternalServerError",
			Code:    500,
		})
	}

	if res.Error == "user canceled request" {
		c.Log.Warn("user canceled request")
		return c.JSON(500, shared.OpenAIError{
			Message: "User cancelled request",
			Object:  "error",
			Type:    "InternalServerError",
			Code:    400,
		})
	}

	// Save request in background
	go database.SaveRequest(c.Cfg.SqlClient, c.Cfg.ReadSqlClient, res, request, c.Log)

	if res.Success {
		return c.String(200, "")
	}

	if len(res.Responses) > 15 {
		c.Log.Warnw(
			"failed request mid stream, canceling request",
			"error", res.Error,
			"final", "true",
			"status", "partial",
			"duration", fmt.Sprintf("%d", time.Since(request.StartTime)/time.Millisecond),
		)
		return c.JSON(500, shared.OpenAIError{
			Message: "Failed mid-generation, please retry",
			Object:  "error",
			Type:    "InternalServerError",
			Code:    500,
		})
	}

	if c.Cfg.Env.Debug {
		c.Log.Warnw("skipping fallback due to debug flag", "error", res.Error)
		return c.String(500, "")
	}

	c.Log.Warnw(
		"failed request, sending to fallback",
		"error", res.Error,
	)
	qerr := QueryFallback(c, request)
	if qerr != nil {
		c.Log.Warnw("Failed fallback", "error", qerr.Error(), "final", "true", "status", "failed")
		return c.JSON(503, shared.OpenAIError{
			Message: qerr.Error(),
			Object:  "error",
			Type:    "APITimeoutError",
			Code:    qerr.StatusCode,
		})
	}

	return c.String(200, "")
}
