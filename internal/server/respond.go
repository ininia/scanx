package server

import (
	"encoding/json"
	"log/slog"
	"net/http"
)

// ErrorBody is the JSON error envelope defined in spec §9.
type ErrorBody struct {
	Error ErrorDetail `json:"error"`
}

// ErrorDetail carries a stable machine code, a user-safe message and the
// request id for correlating with server logs.
type ErrorDetail struct {
	Code      string `json:"code"`
	Message   string `json:"message"`
	RequestID string `json:"request_id,omitempty"`
}

// WriteJSON writes v as JSON with the given status.
func WriteJSON(w http.ResponseWriter, r *http.Request, status int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(v); err != nil {
		slog.WarnContext(r.Context(), "write json response", "err", err)
	}
}

// WriteError writes the standard error envelope. message must never contain
// internal details; those belong in logs only.
func WriteError(w http.ResponseWriter, r *http.Request, status int, code, message string) {
	WriteJSON(w, r, status, ErrorBody{Error: ErrorDetail{
		Code:      code,
		Message:   message,
		RequestID: RequestIDFrom(r.Context()),
	}})
}
