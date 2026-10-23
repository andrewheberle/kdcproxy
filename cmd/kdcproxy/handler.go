package main

import (
	"context"
	"log/slog"
	"net/http"

	sloghttp "github.com/samber/slog-http"
)

// droppedKey is the context key for the flag recovery sets when it drops a connection
type droppedKey struct{}

// newHandler wraps next with panic recovery and access logging
func newHandler(logger *slog.Logger, next http.Handler) http.Handler {
	// recovery logs a dropped connection itself, as the access log would
	// report it as a 200 with nothing written
	config := sloghttp.DefaultConfig()
	config.Filters = append(config.Filters, func(_ sloghttp.WrapResponseWriter, r *http.Request) bool {
		return !wasDropped(r)
	})

	handler := recovery(logger)(next)
	handler = sloghttp.NewWithConfig(logger, config)(handler)

	// outermost, so the access log sees the flag set by recovery
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		handler.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), droppedKey{}, new(bool))))
	})
}

// markDropped records that the connection for r is being dropped
func markDropped(r *http.Request) {
	if dropped, ok := r.Context().Value(droppedKey{}).(*bool); ok {
		*dropped = true
	}
}

// wasDropped reports whether the connection for r was dropped
func wasDropped(r *http.Request) bool {
	dropped, ok := r.Context().Value(droppedKey{}).(*bool)

	return ok && *dropped
}
