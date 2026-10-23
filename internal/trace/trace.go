package trace

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"log/slog"
	"net/http"
	"time"
)

type ctxKey struct{}

// Span is a lightweight request span (not full OTel).
type Span struct {
	TraceID  string
	Name     string
	Started  time.Time
	Attrs    map[string]string
}

func NewID() string {
	var b [8]byte
	_, _ = rand.Read(b[:])
	return hex.EncodeToString(b[:])
}

func FromRequest(r *http.Request) string {
	if id := r.Header.Get("X-Request-ID"); id != "" {
		return id
	}
	if id := r.Header.Get("X-Trace-Id"); id != "" {
		return id
	}
	return NewID()
}

func WithSpan(ctx context.Context, sp *Span) context.Context {
	return context.WithValue(ctx, ctxKey{}, sp)
}

func SpanFromContext(ctx context.Context) *Span {
	sp, _ := ctx.Value(ctxKey{}).(*Span)
	return sp
}

func Start(ctx context.Context, name string) (*Span, context.Context) {
	parent := SpanFromContext(ctx)
	id := NewID()
	if parent != nil && parent.TraceID != "" {
		id = parent.TraceID
	}
	sp := &Span{TraceID: id, Name: name, Started: time.Now(), Attrs: map[string]string{}}
	return sp, WithSpan(ctx, sp)
}

func (sp *Span) End(log *slog.Logger, err error) {
	if sp == nil {
		return
	}
	lat := time.Since(sp.Started)
	if log == nil {
		return
	}
	args := []any{"trace_id", sp.TraceID, "span", sp.Name, "latency_ms", lat.Milliseconds()}
	for k, v := range sp.Attrs {
		args = append(args, k, v)
	}
	if err != nil {
		args = append(args, "err", err)
		log.Warn("trace", args...)
		return
	}
	log.Debug("trace", args...)
}

// Middleware injects X-Request-ID and a root span into the request context.
func Middleware(log *slog.Logger, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id := FromRequest(r)
		w.Header().Set("X-Request-ID", id)
		sp := &Span{TraceID: id, Name: r.Method + " " + r.URL.Path, Started: time.Now(), Attrs: map[string]string{
			"remote": r.RemoteAddr,
		}}
		ctx := WithSpan(r.Context(), sp)
		next.ServeHTTP(w, r.WithContext(ctx))
		sp.End(log, nil)
	})
}
