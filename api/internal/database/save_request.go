package database

import (
	"database/sql"
	"encoding/json"
	"fmt"

	"api/internal/shared"

	"go.uber.org/zap"
)

func SaveRequest(sqlClient *sql.DB, res *shared.ResponseInfo, req *shared.RequestInfo, logger *zap.SugaredLogger) {
	var (
		model_id int
		cpt      int
	)
	var bodyJson map[string]interface{}
	err := json.Unmarshal(req.Body, &bodyJson)
	if err != nil {
		logger.Warnf("Failed unmasrhaling request body: %s", string(req.Body))
		return
	}
	model, ok := bodyJson["model"]
	if !ok {
		logger.Error("No model in body")
		return
	}
	err = sqlClient.QueryRow("SELECT id, cpt FROM model WHERE name = ?", model.(string)).
		Scan(&model_id, &cpt)
	if err != nil {
		logger.Warnw("Failed to get model "+model.(string), "error", err.Error())
		return
	}

	// Update credits
	usedCredits := 0
	if res.Type == shared.ENDPOINTS.COMPLETION {
		usedCredits = res.ResponseTokens * cpt
	}
	if res.Type == shared.ENDPOINTS.CHAT {
		usedCredits = res.ResponseTokens * cpt
	}
	if !req.Chargeable {
		usedCredits = 0
	}

	if usedCredits != 0 {
		_, err = sqlClient.Exec("UPDATE user SET credits=? WHERE id=?",
			max(req.StartingCredits-int64(usedCredits), 0),
			req.UserId)
		if err != nil {
			logger.Errorf("Failed to update credits: %d - %d\n%s\n", req.StartingCredits, usedCredits, err)
		}
	}

	var responseJson []byte
	var timeForFirstToken int64 = 0
	timeForFirstToken = res.TimeToFirstToken
	responseJson, err = json.Marshal(res.Responses)

	if err != nil {
		logger.Errorw("Failed to parse json: "+string(responseJson), "error", err.Error())
	}

	_, err = sqlClient.Exec(`
	INSERT INTO 
		request (pub_id, user_id, credits_used, request, response, model_id, uid, hotkey, coldkey, miner_address, endpoint, success, time_to_first_token, total_time, scored)
		VALUES	(?,      ?,       ?,            ?,       ?,        ?,        ?,   ?,      ?,       ?,             ?,        ?,       ?,                   ?,          ?)`,
		req.Id,
		req.UserId,
		0,
		string(req.Body),
		NewNullString(string(responseJson)),
		model_id,
		res.Miner.Uid,
		res.Miner.Hotkey,
		res.Miner.Coldkey,
		fmt.Sprintf("http://%s:%d",
			res.Miner.Ip,
			res.Miner.Port),
		req.Endpoint,
		res.Success,
		timeForFirstToken,
		res.TotalTime,
		req.Miner != nil,
	)
	if err != nil {
		logger.Errorw("Failed to update", "error", err.Error())
		return
	}
}

func NewNullString(s string) sql.NullString {
	if len(s) == 0 {
		return sql.NullString{}
	}
	return sql.NullString{
		String: s,
		Valid:  true,
	}
}
