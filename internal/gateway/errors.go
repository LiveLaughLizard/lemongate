package gateway

import (
	"encoding/json"
	"net/http"
)

// APIError is an OpenAI-compatible error body.
type APIError struct {
	Status  int    `json:"-"`
	Message string `json:"message"`
	Type    string `json:"type"`
	Code    string `json:"code,omitempty"`
	Param   string `json:"param,omitempty"`
}

func (e *APIError) Error() string { return e.Message }

func WriteError(w http.ResponseWriter, e *APIError) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(e.Status)
	_ = json.NewEncoder(w).Encode(map[string]any{"error": e})
}

func errBadRequest(msg string) *APIError {
	return &APIError{Status: http.StatusBadRequest, Message: msg, Type: "invalid_request_error"}
}

func errAuth(msg string) *APIError {
	return &APIError{Status: http.StatusUnauthorized, Message: msg, Type: "authentication_error", Code: "invalid_api_key"}
}

func errForbidden(msg string) *APIError {
	return &APIError{Status: http.StatusForbidden, Message: msg, Type: "permission_error", Code: "model_not_allowed"}
}

func errNotFound(msg string) *APIError {
	return &APIError{Status: http.StatusNotFound, Message: msg, Type: "invalid_request_error", Code: "model_not_found"}
}
