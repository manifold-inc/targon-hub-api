package routes

import (
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

	qerr := QueryModels(c, request)
	// TODO @ahmed populate this correctly
	go database.SaveRequest(c.Cfg.SqlClient, c.Cfg.ReadSqlClient, &shared.ResponseInfo{}, request, c.Log)
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
