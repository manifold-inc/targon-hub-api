package main

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"math"
	"math/rand"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/ChainSafe/go-schnorrkel"
	"github.com/aidarkhanov/nanoid"
	"github.com/google/uuid"
	"github.com/nitishm/go-rejson/v4"
)

func safeEnv(env string) string {
	// Lookup env variable, and panic if not present

	res, present := os.LookupEnv(env)
	if !present {
		log.Fatalf("Missing environment variable %s", env)
	}
	return res
}

func signMessage(message []byte, public string, private string) string {
	// Signs a message via schnorrkel pub and private keys

	var pubk [32]byte
	data, err := hex.DecodeString(public)
	if err != nil {
		log.Fatalf("Failed to decode public key: %s", err)
	}
	copy(pubk[:], data)

	var prik [32]byte
	data, err = hex.DecodeString(private)
	if err != nil {
		log.Fatalf("Failed to decode private key: %s", err)
	}
	copy(prik[:], data)

	priv := schnorrkel.SecretKey{}
	priv.Decode(prik)
	pub := schnorrkel.PublicKey{}
	pub.Decode(pubk)

	signingCtx := []byte("substrate")
	signingTranscript := schnorrkel.NewSigningContext(signingCtx, message)
	sig, _ := priv.Sign(signingTranscript)
	sigEncode := sig.Encode()
	out := hex.EncodeToString(sigEncode[:])

	return "0x" + out
}

func sha256Hash(str []byte) string {
	h := sha256.New()
	h.Write(str)
	sum := h.Sum(nil)
	return hex.EncodeToString(sum)
}

func getTopMiners(c *Context) []Miner {
	rh := rejson.NewReJSONHandler()
	rh.SetGoRedisClientWithContext(c.Request().Context(), client)
	minerJSON, err := rh.JSONGet("miners", ".")
	if err != nil {
		c.Err.Printf("Failed to JSONGet: %s\n", err.Error())
		return nil
	}

	var miners []Miner
	err = json.Unmarshal(minerJSON.([]byte), &miners)
	if err != nil {
		c.Err.Printf("Failed to JSON Unmarshal: %s\n", err.Error())
		return nil
	}
	for i := range miners {
		j := rand.Intn(i + 1)
		miners[i], miners[j] = miners[j], miners[i]
	}
	return miners
}

func queryMiners(c *Context, req []byte) (ResponseInfo, error) {
	// Query miners with llm request

	// First we get our miners
	miners := getTopMiners(c)
	if miners == nil {
		return ResponseInfo{}, errors.New("No Miners")
	}

	// Build the rest of the body hash
	tr := &http.Transport{
		MaxIdleConns:      10,
		IdleConnTimeout:   30 * time.Second,
		DisableKeepAlives: false,
	}
	httpClient := http.Client{Transport: tr, Timeout: 10 * time.Second}

	// query each miner at the same time with the variable context of the
	// parent function via go routines
	for index, miner := range miners {
		tokens := 0
		endpoint := "http://" + miner.Ip + ":" + fmt.Sprint(miner.Port) + "/v1/chat/completions"
		timestamp := time.Now().UnixMilli()
		id := uuid.New().String()
		timestampInterval := int64(math.Ceil(float64(timestamp) / 1e4))

		bodyHash := sha256Hash(req)
		message := fmt.Sprintf("%s.%s.%d.%s", bodyHash, id, timestamp, miner.Hotkey)
		requestSignature := signMessage([]byte(message), PUBLIC_KEY, PRIVATE_KEY)

		headers := map[string]string{
			"Epistula-Version":            "2",
			"Epistula-Timestamp":          fmt.Sprintf("%d", timestamp),
			"Epistula-Uuid":               id,
			"Epistula-Signed-By":          HOTKEY,
			"Epistula-Signed-For":         miner.Hotkey,
			"Epistula-Request-Signature":  requestSignature,
			"Epistula-Secret-Signature-0": signMessage([]byte(fmt.Sprintf("%d.%s", timestampInterval-1, miner.Hotkey)), PUBLIC_KEY, PRIVATE_KEY),
			"Epistula-Secret-Signature-1": signMessage([]byte(fmt.Sprintf("%d.%s", timestampInterval, miner.Hotkey)), PUBLIC_KEY, PRIVATE_KEY),
			"Epistula-Secret-Signature-2": signMessage([]byte(fmt.Sprintf("%d.%s", timestampInterval+1, miner.Hotkey)), PUBLIC_KEY, PRIVATE_KEY),
			"Content-Type":                "application/json",
			"Connection":                  "keep-alive",
		}

		r, err := http.NewRequest("POST", endpoint, bytes.NewBuffer(req))
		if err != nil {
			c.Warn.Printf("Failed miner request: %s\n", err.Error())
			continue
		}

		// Set headers
		for key, value := range headers {
			r.Header.Set(key, value)
		}
		r.Close = true
		r.WithContext(c.Request().Context())

		res, err := httpClient.Do(r)
		if err != nil {
			c.Warn.Printf("Miner: %s %s\nError: %s\n", miner.Hotkey, miner.Coldkey, err.Error())
			if res != nil {
				res.Body.Close()
			}
			continue
		}
		if res.StatusCode != http.StatusOK {
			bdy, _ := io.ReadAll(res.Body)
			res.Body.Close()
			c.Warn.Printf("Miner: %s %s\nError: %s\n", miner.Hotkey, miner.Coldkey, string(bdy))
			continue
		}

		c.Info.Printf("Attempt: %d Miner: %s %s\n", index, miner.Hotkey, miner.Coldkey)
		reader := bufio.NewScanner(res.Body)
		finished := false
		var response map[string]interface{}
		var responses []map[string]interface{}
		for reader.Scan() {
			select {
			case <-c.Request().Context().Done():
				return ResponseInfo{}, errors.New("Request Canceled")
			default:
				token := reader.Text()
				fmt.Fprintf(c.Response(), token+"\n\n")
				c.Response().Flush()
				if token == "data: [DONE]" {
					finished = true
					break
				}
				token, found := strings.CutPrefix(token, "data: ")
				if found {
					tokens += 1
					err := json.Unmarshal([]byte(token), &response)
					if err != nil {
						c.Err.Printf("Failed decoing token string: %s", err)
						continue
					}
					responses = append(responses, response)
				}
			}
		}
		res.Body.Close()
		if finished == false {
			continue
		}
		return ResponseInfo{Miner: miner, Attempt: index, Tokens: tokens, Responses: responses}, nil
	}
	return ResponseInfo{}, errors.New("Ran out of miners to query")
}

func saveRequest(db *sql.DB, res ResponseInfo, req []byte, logger *log.Logger) {
	var (
		model string
		cpt   int
	)
	var bodyJson map[string]interface{}
	json.Unmarshal(req, &bodyJson)
	mdl, ok := bodyJson["model"]
	if !ok {
		logger.Println("No model in body")
		return
	}
	err := db.QueryRow("SELECT id, cpt FROM model WHERE enabled = true AND id = ?", mdl.(string)).Scan(&model, &cpt)
	if err != nil {
		logger.Println("Failed get model")
		logger.Println(err)
	}
	_, err = db.Exec("UPDATE user SET credits=? WHERE id=?",
		res.StartingCredits-(res.Tokens*cpt),
		res.UserId)
	if err != nil {
		logger.Println("Failed to update")
		logger.Println(err)
	}

	responseJson, _ := json.Marshal(res.Responses)
	pubId, _ := nanoid.Generate("0123456789abcdefghijklmnopqrstuvwxyz", 28)
	pubId = "req_" + pubId
	_, err = db.Exec(`
	INSERT INTO 
		request (pub_id, user_id, credits_used, tokens, request, response, model_id, uid, hotkey, coldkey, miner_address, attempt) 
		VALUES	(?,      ?,       ?,            ?,      ?,       ?,        ?,     ?,   ?,      ?,       ?,            ?)`,
		pubId,
		res.UserId,
		res.Tokens*cpt,
		res.Tokens,
		string(req),
		string(responseJson),
		model,
		res.Miner.Uid,
		res.Miner.Hotkey,
		res.Miner.Coldkey,
		fmt.Sprintf("http://%s:%d",
			res.Miner.Ip,
			res.Miner.Port),
		res.Attempt)

	if err != nil {
		logger.Println("Failed to update")
		logger.Println(err)
		return
	}
	return
}
