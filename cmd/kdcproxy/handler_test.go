package main

import (
	"bytes"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
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

// withMsg returns the log lines with message msg
func withMsg(lines []map[string]any, msg string) []map[string]any {
	var found []map[string]any
	for _, l := range lines {
		if l["msg"] == msg {
			found = append(found, l)
		}
	}

	return found
}

func TestNewHandler(t *testing.T) {
	tests := []struct {
		name        string
		handler     http.HandlerFunc
		wantPanic   any
		wantStatus  int
		wantMsgs    map[string]int
		wantDropped bool
	}{
		{
			name: "ok",
			handler: func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusOK)
			},
			wantStatus: http.StatusOK,
			wantMsgs:   map[string]int{"200: OK": 1, "connection dropped": 0},
		},
		{
			name: "dropped",
			handler: func(w http.ResponseWriter, r *http.Request) {
				panic(http.ErrAbortHandler)
			},
			wantPanic:   http.ErrAbortHandler,
			wantMsgs:    map[string]int{"200: OK": 0, "connection dropped": 1},
			wantDropped: true,
		},
		{
			name: "other_panic",
			handler: func(w http.ResponseWriter, r *http.Request) {
				panic("boom")
			},
			wantStatus: http.StatusInternalServerError,
			wantMsgs:   map[string]int{"panic recovered": 1, "500: Internal Server Error": 1, "connection dropped": 0},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var logs bytes.Buffer
			logger := slog.New(slog.NewJSONHandler(&logs, nil))
			w := httptest.NewRecorder()
			r := httptest.NewRequest(http.MethodPost, "/KdcProxy", nil)
			r.RemoteAddr = "192.0.2.1:1234"

			func() {
				defer func() {
					if got := recover(); got != tt.wantPanic {
						t.Errorf("panic = %v, want %v", got, tt.wantPanic)
					}
				}()
				newHandler(logger, tt.handler).ServeHTTP(w, r)
			}()

			if tt.wantPanic == nil && w.Code != tt.wantStatus {
				t.Errorf("status = %d, want %d", w.Code, tt.wantStatus)
			}

			lines := logLines(t, logs.Bytes())
			for msg, want := range tt.wantMsgs {
				if got := len(withMsg(lines, msg)); got != want {
					t.Errorf("%q logged %d times, want %d:\n%s", msg, got, want, logs.String())
				}
			}

			if !tt.wantDropped {
				return
			}
			dropped := withMsg(lines, "connection dropped")
			if len(dropped) != 1 {
				return
			}
			line := dropped[0]
			if line["level"] != "WARN" {
				t.Errorf("level = %v, want WARN", line["level"])
			}
			if id, _ := line["id"].(string); id == "" {
				t.Errorf("id = %v, want the request id", line["id"])
			}
			request, _ := line["request"].(map[string]any)
			for key, want := range map[string]string{"method": http.MethodPost, "path": "/KdcProxy", "ip": "192.0.2.1:1234"} {
				if request[key] != want {
					t.Errorf("request.%s = %v, want %q", key, request[key], want)
				}
			}
		})
	}
}
