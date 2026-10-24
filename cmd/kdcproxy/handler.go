package main

import (
	"crypto/rand"
	"encoding/hex"
	"io"
	"log/slog"
	"net/http"
	"runtime/debug"
	"time"
)

// requestIDHeader is the header a request id is taken from, when the client
// or a reverse proxy sets one
const requestIDHeader = "X-Request-Id"

// newHandler wraps next with access logging and panic recovery. Each request
// is logged once:
//   - "request" when a response is sent
//   - "connection dropped" when next panics with http.ErrAbortHandler, which
//     is re-panicked so net/http drops the connection without a response
//   - "panic recovered" for any other panic, which is answered with a 500
func newHandler(logger *slog.Logger, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()

		id := r.Header.Get(requestIDHeader)
		if id == "" {
			id = newRequestID()
		}

		body := &countingReader{ReadCloser: r.Body}
		if r.Body != nil {
			r.Body = body
		}
		rw := &responseRecorder{ResponseWriter: w}

		defer func() {
			err := recover()

			attrs := []slog.Attr{
				slog.String("id", id),
				slog.String("method", r.Method),
				slog.String("path", r.URL.Path),
			}
			// a dropped connection has no status or response
			if err != http.ErrAbortHandler {
				if err != nil && rw.status == 0 {
					rw.WriteHeader(http.StatusInternalServerError)
				}
				attrs = append(attrs,
					slog.Int("status", rw.statusCode()),
					slog.Int64("response_bytes", rw.bytes),
				)
			}
			attrs = append(attrs,
				slog.Int64("request_bytes", body.bytes),
				slog.Duration("duration", time.Since(start)),
				slog.String("ip", r.RemoteAddr),
			)
			// recorded as sent, as it is set by the client or a reverse proxy
			if forwarded := r.Header.Get("X-Forwarded-For"); forwarded != "" {
				attrs = append(attrs, slog.String("forwarded_for", forwarded))
			}
			attrs = append(attrs, slog.String("user_agent", r.UserAgent()))

			switch {
			case err == http.ErrAbortHandler:
				logger.LogAttrs(r.Context(), slog.LevelWarn, "connection dropped", attrs...)
				panic(err)
			case err != nil:
				attrs = append(attrs, slog.Any("error", err), slog.String("stack", string(debug.Stack())))
				logger.LogAttrs(r.Context(), slog.LevelError, "panic recovered", attrs...)
			default:
				logger.LogAttrs(r.Context(), level(rw.statusCode()), "request", attrs...)
			}
		}()

		next.ServeHTTP(rw, r)
	})
}

// level returns the log level for a response with status
func level(status int) slog.Level {
	switch {
	case status >= http.StatusInternalServerError:
		return slog.LevelError
	case status >= http.StatusBadRequest:
		return slog.LevelWarn
	default:
		return slog.LevelInfo
	}
}

// newRequestID returns a random 32 character hex request id
func newRequestID() string {
	b := make([]byte, 16)
	// crypto/rand.Read never returns an error
	_, _ = rand.Read(b)

	return hex.EncodeToString(b)
}

// countingReader counts the bytes read from a request body
type countingReader struct {
	io.ReadCloser
	bytes int64
}

func (r *countingReader) Read(p []byte) (int, error) {
	n, err := r.ReadCloser.Read(p)
	r.bytes += int64(n)

	return n, err
}

// responseRecorder records the status and the number of bytes written for a response
type responseRecorder struct {
	http.ResponseWriter
	status int
	bytes  int64
}

func (w *responseRecorder) WriteHeader(status int) {
	if w.status == 0 {
		w.status = status
	}
	w.ResponseWriter.WriteHeader(status)
}

func (w *responseRecorder) Write(b []byte) (int, error) {
	if w.status == 0 {
		w.status = http.StatusOK
	}
	n, err := w.ResponseWriter.Write(b)
	w.bytes += int64(n)

	return n, err
}

// Unwrap lets http.ResponseController reach the underlying http.ResponseWriter
func (w *responseRecorder) Unwrap() http.ResponseWriter {
	return w.ResponseWriter
}

// statusCode returns the status sent, which is 200 if next wrote nothing
func (w *responseRecorder) statusCode() int {
	if w.status == 0 {
		return http.StatusOK
	}

	return w.status
}
