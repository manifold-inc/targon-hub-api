package database

import (
	"database/sql"
	"encoding/json"
	"sync"

	"api/internal/shared"

	"go.uber.org/zap"
)

type UserMutex struct {
	mu   sync.Mutex
	umap map[int]*sync.Mutex
}

var userMutexes = UserMutex{umap: make(map[int]*sync.Mutex)}

func SaveRequest(sqlClient *sql.DB, readSqlClient *sql.DB, res *shared.ResponseInfo, req *shared.RequestInfo, logger *zap.SugaredLogger) {
	userMutexes.mu.Lock()
	if _, ok := userMutexes.umap[req.UserId]; !ok {
		userMutexes.umap[req.UserId] = &sync.Mutex{}
	}
	userMutexes.mu.Unlock()

	var (
		model_id int
		cpt      int
	)
	var bodyJson map[string]any
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
	err = readSqlClient.QueryRow("SELECT id, cpt FROM model WHERE name = ?", model.(string)).
		Scan(&model_id, &cpt)
	if err != nil {
		logger.Warnw("Failed to get model "+model.(string), "error", err.Error())
		return
	}

	// Update credits
	usedCredits := int64(0)
	input_tokens_approx := max(len(string(req.Body))/10, 1)
	if res != nil {
		usedCredits = (int64(res.ResponseTokens) + int64(input_tokens_approx)) * int64(cpt)
	}

	if !req.Chargeable {
		usedCredits = 0
	}

	userMutexes.umap[req.UserId].Lock()
	var startingCredits int64
	err = readSqlClient.QueryRow("SELECT user.credits FROM user  WHERE user.id = ?", req.UserId).
		Scan(&startingCredits)
	if err == sql.ErrNoRows {
		logger.Warnf("no user found for user id %d", req.UserId)
		startingCredits = req.StartingCredits
	}
	if err != nil {
		logger.Errorw("Error fetching user data from api key", "error", err)
		startingCredits = req.StartingCredits
	}
	total_credits_used := int64(0)
	if usedCredits != 0 {
		total_credits_used = max(startingCredits-(usedCredits), 0)
		_, err = sqlClient.Exec("UPDATE user SET credits=? WHERE id=?",
			total_credits_used,
			req.UserId)
		if err != nil {
			logger.Errorf("Failed to update credits: %d - %d\n%s\n", req.StartingCredits, usedCredits, err)
		}
	}
	userMutexes.umap[req.UserId].Unlock()

	var timeForFirstToken int32 = 0
	var totalTime int32 = 0
	if res != nil {
		timeForFirstToken = res.TimeToFirstToken
		totalTime = res.TotalTime
	}

	_, err = sqlClient.Exec(`
	INSERT INTO 
		request (pub_id, user_id, used_credits, request, response, model_id, uid, hotkey, coldkey, miner_address, endpoint, success, time_to_first_token, total_time, scored)
		VALUES	(?,      ?,       ?,            ?,       ?,        ?,        ?,   ?,      ?,       ?,             ?,        ?,       ?,                   ?,          ?)`,
		req.Id,
		req.UserId,
		total_credits_used,
		string(req.Body),
		res.ResponseTokensString,
		model_id,
		0,
		"",
		"",
		"",
		req.Endpoint,
		res != nil,
		timeForFirstToken,
		totalTime,
		1,
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
