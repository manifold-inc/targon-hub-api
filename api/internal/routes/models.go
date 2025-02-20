package routes

import (
	"api/internal/shared"
	"strings"
	"time"

	"github.com/labstack/echo/v4"
)

type Model struct {
	ID      string `json:"id"`
	Object  string `json:"object"`
	Created int64  `json:"created"`
	OwnedBy string `json:"owned_by"`
}

type ModelList struct {
	Object string  `json:"object"`
	Data   []Model `json:"data"`
}

func Models(cc echo.Context) error {
	c := cc.(*shared.Context)
	defer c.Log.Sync()

	rows, err := c.Cfg.SqlClient.Query(`
			SELECT name, DATE_FORMAT(created_at, '%Y-%m-%d %H:%i:%s') as created_at 
			FROM model WHERE enabled = 1
		`)
	if err != nil {
		c.Log.Errorw("Failed to get models", "error", err.Error())
		return c.String(500, "Failed to get models")
	}
	defer rows.Close()

	var models []Model
	for rows.Next() {
		var model Model
		var createdAtStr string
		if err := rows.Scan(&model.ID, &createdAtStr); err != nil {
			c.Log.Errorw("Failed to scan model row", "error", err.Error())
			return c.String(500, "Failed to get models")
		}

		createdAt, err := time.Parse("2006-01-02 15:04:05", createdAtStr)
		if err != nil {
			c.Log.Errorw("Failed to parse created_at", "error", err.Error())
			return c.String(500, "Failed to get models")
		}

		model.Object = "model"
		model.Created = createdAt.Unix()
		model.OwnedBy = strings.Split(model.ID, "/")[0]

		models = append(models, model)
	}

	if err = rows.Err(); err != nil {
		c.Log.Error("Error iterating model rows", "error", err.Error())
		return c.String(500, "Failed to get models")
	}

	return c.JSON(200, ModelList{
		Object: "list",
		Data:   models,
	})
}
