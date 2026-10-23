package main

import (
	"bytes"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestRecovery(t *testing.T) {
	tests := []struct {
		name       string
		handler    http.HandlerFunc
		wantPanic  any
		wantStatus int
		wantLog    string
	}{
		{
			name: "no_panic",
			handler: func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusNoContent)
			},
			wantStatus: http.StatusNoContent,
		},
		{
			name: "abort_handler_repanics",
			handler: func(w http.ResponseWriter, r *http.Request) {
				panic(http.ErrAbortHandler)
			},
			wantPanic: http.ErrAbortHandler,
		},
		{
			name: "other_panic_logged",
			handler: func(w http.ResponseWriter, r *http.Request) {
				panic("boom")
			},
			wantStatus: http.StatusInternalServerError,
			wantLog:    "boom",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var logs bytes.Buffer
			logger := slog.New(slog.NewTextHandler(&logs, nil))
			w := httptest.NewRecorder()
			r := httptest.NewRequest(http.MethodGet, "/", nil)

			defer func() {
				if got := recover(); got != tt.wantPanic {
					t.Fatalf("panic = %v, want %v", got, tt.wantPanic)
				}
				if tt.wantPanic != nil {
					return
				}
				if w.Code != tt.wantStatus {
					t.Errorf("status = %d, want %d", w.Code, tt.wantStatus)
				}
				if !strings.Contains(logs.String(), tt.wantLog) {
					t.Errorf("logs = %q, want to contain %q", logs.String(), tt.wantLog)
				}
			}()
			recovery(logger)(tt.handler).ServeHTTP(w, r)
		})
	}
}
