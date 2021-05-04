package fleet

import (
	"encoding/json"
	"net/http"
)

type errResp struct {
	StatusCode int    `json:"statusCode"`
	Error      string `json:"error"`
	Message    string `json:"message"`
}

func WriteError(w http.ResponseWriter, code int, errStr string, msg string) error {
	data, err := json.Marshal(&errResp{StatusCode: code, Error: errStr, Message: msg})
	if err != nil {
		return err
	}
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.WriteHeader(code)
	w.Write(data)
	return nil
}
