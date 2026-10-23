package main

import (
	"log/slog"
	"net/http"
	"runtime/debug"
)

// recovery recovers panics from next and responds with a 500, except for
// http.ErrAbortHandler, which is re-panicked so net/http drops the connection.
// sloghttp.Recovery swallows http.ErrAbortHandler, so it cannot be used.
func recovery(logger *slog.Logger) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			defer func() {
				err := recover()
				if err == nil {
					return
				}
				if err == http.ErrAbortHandler {
					panic(err)
				}

				logger.Error("panic recovered", "error", err, "stack", string(debug.Stack()))
				w.WriteHeader(http.StatusInternalServerError)
			}()

			next.ServeHTTP(w, r)
		})
	}
}
