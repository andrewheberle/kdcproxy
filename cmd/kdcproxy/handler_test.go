package main

import (
	"bytes"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"testing"
)

// logLines decodes JSON log output into one map per line
func logLines(t *testing.T, b []byte) []map[string]any {
	t.Helper()

	var lines []map[string]any
	for line := range bytes.Lines(b) {
		var m map[string]any
		if err := json.Unmarshal(line, &m); err != nil {
			t.Fatalf("decoding log line %q: %v", line, err)
		}
		lines = append(lines, m)
	}

	return lines
}

var hexID = regexp.MustCompile(`^[0-9a-f]{32}$`)

func TestNewHandler(t *testing.T) {
	// reads the request body and replies with "hello"
	hello := func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.ReadAll(r.Body)
		_, _ = w.Write([]byte("hello"))
	}

	tests := []struct {
		name          string
		handler       http.HandlerFunc
		header        map[string]string
		wantPanic     any
		wantMsg       string
		wantLevel     string
		wantStatus    int // 0 when no status is logged
		wantRespBytes float64
		wantReqBytes  float64
		wantID        string // empty for a generated id
		wantForwarded string // empty when not logged
		wantError     string // empty when not logged
	}{
		{
			name:          "ok",
			handler:       hello,
			wantMsg:       "request",
			wantLevel:     "INFO",
			wantStatus:    http.StatusOK,
			wantRespBytes: 5,
			wantReqBytes:  7,
		},
		{
			name:       "nothing_written",
			handler:    func(w http.ResponseWriter, r *http.Request) {},
			wantMsg:    "request",
			wantLevel:  "INFO",
			wantStatus: http.StatusOK,
		},
		{
			name: "client_error",
			handler: func(w http.ResponseWriter, r *http.Request) {
				http.Error(w, "Invalid request", http.StatusBadRequest)
			},
			wantMsg:       "request",
			wantLevel:     "WARN",
			wantStatus:    http.StatusBadRequest,
			wantRespBytes: float64(len("Invalid request\n")),
		},
		{
			name: "server_error",
			handler: func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusServiceUnavailable)
			},
			wantMsg:    "request",
			wantLevel:  "ERROR",
			wantStatus: http.StatusServiceUnavailable,
		},
		{
			name: "dropped",
			handler: func(w http.ResponseWriter, r *http.Request) {
				_, _ = io.ReadAll(r.Body)
				panic(http.ErrAbortHandler)
			},
			wantPanic:    http.ErrAbortHandler,
			wantMsg:      "connection dropped",
			wantLevel:    "WARN",
			wantReqBytes: 7,
		},
		{
			name: "other_panic",
			handler: func(w http.ResponseWriter, r *http.Request) {
				panic("boom")
			},
			wantMsg:    "panic recovered",
			wantLevel:  "ERROR",
			wantStatus: http.StatusInternalServerError,
			wantError:  "boom",
		},
		{
			name:          "request_id_from_header",
			handler:       hello,
			header:        map[string]string{requestIDHeader: "abc-123"},
			wantMsg:       "request",
			wantLevel:     "INFO",
			wantStatus:    http.StatusOK,
			wantRespBytes: 5,
			wantReqBytes:  7,
			wantID:        "abc-123",
		},
		{
			name:          "forwarded_for",
			handler:       hello,
			header:        map[string]string{"X-Forwarded-For": "198.51.100.7, 192.0.2.1"},
			wantMsg:       "request",
			wantLevel:     "INFO",
			wantStatus:    http.StatusOK,
			wantRespBytes: 5,
			wantReqBytes:  7,
			wantForwarded: "198.51.100.7, 192.0.2.1",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var logs bytes.Buffer
			logger := slog.New(slog.NewJSONHandler(&logs, nil))
			w := httptest.NewRecorder()
			r := httptest.NewRequest(http.MethodPost, "/KdcProxy", strings.NewReader("request"))
			r.RemoteAddr = "192.0.2.1:1234"
			r.Header.Set("User-Agent", "test-agent")
			for k, v := range tt.header {
				r.Header.Set(k, v)
			}

			func() {
				defer func() {
					if got := recover(); got != tt.wantPanic {
						t.Errorf("panic = %v, want %v", got, tt.wantPanic)
					}
				}()
				newHandler(logger, tt.handler).ServeHTTP(w, r)
			}()

			if tt.wantPanic == nil && w.Code != tt.wantStatus {
				t.Errorf("response status = %d, want %d", w.Code, tt.wantStatus)
			}

			lines := logLines(t, logs.Bytes())
			if len(lines) != 1 {
				t.Fatalf("logged %d lines, want 1:\n%s", len(lines), logs.String())
			}
			line := lines[0]

			for key, want := range map[string]any{
				"msg":           tt.wantMsg,
				"level":         tt.wantLevel,
				"method":        http.MethodPost,
				"path":          "/KdcProxy",
				"ip":            "192.0.2.1:1234",
				"user_agent":    "test-agent",
				"request_bytes": tt.wantReqBytes,
			} {
				if line[key] != want {
					t.Errorf("%s = %v, want %v", key, line[key], want)
				}
			}
			if _, ok := line["duration"]; !ok {
				t.Errorf("duration not logged")
			}

			if tt.wantStatus == 0 {
				for _, key := range []string{"status", "response_bytes"} {
					if _, ok := line[key]; ok {
						t.Errorf("%s = %v, want it not logged", key, line[key])
					}
				}
			} else {
				if line["status"] != float64(tt.wantStatus) {
					t.Errorf("status = %v, want %d", line["status"], tt.wantStatus)
				}
				if line["response_bytes"] != tt.wantRespBytes {
					t.Errorf("response_bytes = %v, want %v", line["response_bytes"], tt.wantRespBytes)
				}
			}

			id, _ := line["id"].(string)
			if tt.wantID != "" && id != tt.wantID {
				t.Errorf("id = %q, want %q", id, tt.wantID)
			}
			if tt.wantID == "" && !hexID.MatchString(id) {
				t.Errorf("id = %q, want a generated 32 character hex id", id)
			}

			if got, _ := line["forwarded_for"].(string); got != tt.wantForwarded {
				t.Errorf("forwarded_for = %q, want %q", got, tt.wantForwarded)
			}

			if got, _ := line["error"].(string); got != tt.wantError {
				t.Errorf("error = %q, want %q", got, tt.wantError)
			}
			if stack, _ := line["stack"].(string); (tt.wantError != "") != (stack != "") {
				t.Errorf("stack logged = %v, want %v", stack != "", tt.wantError != "")
			}
		})
	}
}
