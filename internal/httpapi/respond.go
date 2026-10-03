package httpapi

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
)

// Error codes from the contract.
const (
	CodeInvalidRequest  = "invalid_request"
	CodeUnauthorized    = "unauthorized"
	CodeForbidden       = "forbidden"
	CodeNotFound        = "not_found"
	CodeConflict        = "conflict"
	CodeRateLimited     = "rate_limited"
	CodePaymentRequired = "payment_required"
	CodeInternal        = "internal"
)

type errorBody struct {
	Error errorDetail `json:"error"`
}

type errorDetail struct {
	Code      string `json:"code"`
	Message   string `json:"message"`
	RequestID string `json:"request_id"`
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if v != nil {
		_ = json.NewEncoder(w).Encode(v)
	}
}

func writeError(w http.ResponseWriter, r *http.Request, status int, code, msg string) {
	writeJSON(w, status, errorBody{Error: errorDetail{Code: code, Message: msg, RequestID: requestIDFrom(r.Context())}})
}

func codeForStatus(status int) string {
	switch status {
	case http.StatusBadRequest, http.StatusRequestEntityTooLarge, http.StatusUnsupportedMediaType:
		return CodeInvalidRequest
	case http.StatusUnauthorized:
		return CodeUnauthorized
	case http.StatusForbidden:
		return CodeForbidden
	case http.StatusNotFound, http.StatusMethodNotAllowed:
		return CodeNotFound
	case http.StatusConflict:
		return CodeConflict
	case http.StatusTooManyRequests:
		return CodeRateLimited
	case http.StatusPaymentRequired:
		return CodePaymentRequired
	}
	return CodeInternal
}

// errBadRequest is a decode error that is safe to show to the client.
type errBadRequest struct{ msg string }

func (e errBadRequest) Error() string { return e.msg }

func badRequest(format string, args ...any) error { return errBadRequest{fmt.Sprintf(format, args...)} }

// decodeJSON decodes exactly one JSON object from the (size-limited) body.
// strict rejects unknown fields, which we do for client-facing endpoints;
// internal service endpoints stay lenient so callers can add fields first.
// allowEmpty treats an empty body as "{}".
func decodeJSON(r *http.Request, dst any, strict, allowEmpty bool) error {
	dec := json.NewDecoder(r.Body)
	if strict {
		dec.DisallowUnknownFields()
	}
	if err := dec.Decode(dst); err != nil {
		var maxErr *http.MaxBytesError
		var syn *json.SyntaxError
		var typ *json.UnmarshalTypeError
		switch {
		case errors.Is(err, io.EOF):
			if allowEmpty {
				return nil
			}
			return badRequest("request body is required")
		case errors.As(err, &maxErr):
			return errTooLarge
		case errors.As(err, &syn), errors.Is(err, io.ErrUnexpectedEOF):
			return badRequest("malformed JSON")
		case errors.As(err, &typ):
			return badRequest("field %q has the wrong type", typ.Field)
		default:
			// Unknown field errors and time parse errors land here; their
			// text names the field but never echoes values.
			return badRequest("invalid request body: %s", sanitizeDecodeErr(err))
		}
	}
	if dec.More() {
		return badRequest("request body must contain a single JSON object")
	}
	return nil
}

var errTooLarge = errors.New("request body too large")

func sanitizeDecodeErr(err error) string {
	msg := err.Error()
	if strings.Contains(msg, "parsing time") {
		return "timestamps must be RFC 3339"
	}
	if len(msg) > 120 {
		msg = msg[:120]
	}
	return msg
}

// writeDecodeError maps decodeJSON errors to responses.
func writeDecodeError(w http.ResponseWriter, r *http.Request, err error) {
	if errors.Is(err, errTooLarge) {
		writeError(w, r, http.StatusRequestEntityTooLarge, CodeInvalidRequest, "request body too large")
		return
	}
	var br errBadRequest
	if errors.As(err, &br) {
		writeError(w, r, http.StatusBadRequest, CodeInvalidRequest, br.msg)
		return
	}
	writeError(w, r, http.StatusBadRequest, CodeInvalidRequest, "invalid request body")
}
