package core

import (
	"encoding/json"
	"log"
	"net/http"
)

// Response is the standard JSON envelope returned by every endpoint.
type Response struct {
	Status  bool        `json:"status"`
	Code    int         `json:"code"`
	Message string      `json:"message"`
	Data    interface{} `json:"data,omitempty"`
	Datas   interface{} `json:"datas,omitempty"`
}

// JSON writes a Response with the given status code.
func JSON(w http.ResponseWriter, code int, status bool, message string, data interface{}, datas interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(Response{
		Status:  status,
		Code:    code,
		Message: message,
		Data:    data,
		Datas:   datas,
	})
}

// Success sends a 200 response carrying a single data object.
func Success(w http.ResponseWriter, message string, data interface{}) {
	JSON(w, http.StatusOK, true, message, data, nil)
}

// SuccessList sends a 200 response carrying a list of data objects.
func SuccessList(w http.ResponseWriter, message string, datas interface{}) {
	JSON(w, http.StatusOK, true, message, nil, datas)
}

// Error sends an error response with the given HTTP status code.
func Error(w http.ResponseWriter, code int, message string) {
	JSON(w, code, false, message, nil, nil)
}

// BadRequest sends a 400 response.
func BadRequest(w http.ResponseWriter, message string) {
	Error(w, http.StatusBadRequest, message)
}

// Unauthorized sends a 401 response.
func Unauthorized(w http.ResponseWriter, message string) {
	Error(w, http.StatusUnauthorized, message)
}

// Forbidden sends a 403 response.
func Forbidden(w http.ResponseWriter, message string) {
	Error(w, http.StatusForbidden, message)
}

// NotFound sends a 404 response.
func NotFound(w http.ResponseWriter, message string) {
	Error(w, http.StatusNotFound, message)
}

// InternalError logs the technical detail server-side and sends a 500
// response. message is safe to show to the client.
func InternalError(w http.ResponseWriter, message string, err error) {
	if err != nil {
		log.Printf("[ERROR] %s: %v", message, err)
	} else {
		log.Printf("[ERROR] %s", message)
	}
	JSON(w, http.StatusInternalServerError, false, message, nil, nil)
}
