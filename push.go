package ingressguard

import (
	"errors"
	"io"
	"net"
	"net/http"
	"strings"
	"time"

	"go.uber.org/zap"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"

	"github.com/honest-hosting/caddy-ingress-guard/bundle"
)

// ensureServer starts the loopback push endpoint, or moves it if push_listen changed.
//
// The endpoint is reachable by tenant PHP at the site tier (shared localhost). That is safe only
// because bundles are self-authenticating: PHP can at most re-deliver a valid, newer bundle for
// this site's own targets. Requests queue for a few slots (admit), and it is never the Caddy
// admin API.
func (rt *runtime) ensureServer() error {
	cfg := rt.cfg.Load()
	rt.srvMu.Lock()
	defer rt.srvMu.Unlock()
	if rt.srv != nil && rt.srvAddr == cfg.pushListen {
		return nil
	}
	if rt.srv != nil {
		_ = rt.srv.Close()
		rt.srv = nil
	}
	ln, err := net.Listen("tcp", cfg.pushListen)
	if err != nil {
		return err
	}
	mux := http.NewServeMux()
	mux.HandleFunc("PUT /v1/bundle", rt.handlePush)
	mux.HandleFunc("GET /v1/status", rt.handleStatus)
	srv := &http.Server{
		Handler:           rt.admit(mux),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      60 * time.Second,
		MaxHeaderBytes:    16 << 10,
	}
	rt.srv, rt.srvAddr = srv, cfg.pushListen
	go func() {
		if err := srv.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
			rt.log().Error("ingress_guard: push endpoint stopped", zap.Error(err))
		}
	}()
	rt.log().Info("ingress_guard: push endpoint listening", zap.String("address", cfg.pushListen))
	return nil
}

// Push endpoint limits (A1 §5.3). Requests wait for a slot instead of being turned away. S2 run 4
// showed why: a 429 budget shared by every local caller let a junk flood from tenant PHP reject
// 59% of the agent's real pushes. Now a flood only delays a real push by its place in the queue,
// and Submit's cheap checks reject the junk.
const (
	pushConcurrency = 2                // requests handled at once; the rest wait in arrival order
	pushQueueWait   = 10 * time.Second // longest wait for a slot, then 429
	pushBodyTimeout = 5 * time.Second  // once admitted, the body must arrive within this
)

// admit runs each request in one of pushConcurrency slots. Waiting requests get a freed slot in
// arrival order: a channel hands it to its longest-waiting sender. A request still waiting after
// pushQueueWait gets 429. The read deadline means a slow sender holds a slot for at most
// pushBodyTimeout. A 4 MiB bundle over loopback takes milliseconds.
func (rt *runtime) admit(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		wait := time.NewTimer(pushQueueWait)
		defer wait.Stop()
		select {
		case rt.pushSlots <- struct{}{}:
		case <-wait.C:
			rt.metrics.rejected.WithLabelValues(bundle.ReasonRateLimited).Inc()
			http.Error(w, bundle.ReasonRateLimited, http.StatusTooManyRequests)
			return
		case <-r.Context().Done():
			return
		}
		defer func() { <-rt.pushSlots }()
		_ = http.NewResponseController(w).SetReadDeadline(time.Now().Add(pushBodyTimeout))
		next.ServeHTTP(w, r)
	})
}

func (rt *runtime) handlePush(w http.ResponseWriter, r *http.Request) {
	raw, err := io.ReadAll(http.MaxBytesReader(w, r.Body, bundle.MaxSignedBundleBytes))
	if err != nil {
		var tooBig *http.MaxBytesError
		if errors.As(err, &tooBig) {
			res := rt.rejected(time.Now(), &bundle.Error{Reason: bundle.ReasonTooLarge})
			writeMessage(w, r, res.status, res.ack)
			return
		}
		http.Error(w, "read error", http.StatusBadRequest)
		return
	}
	res := rt.Submit(raw)
	if !res.ack.GetAccepted() {
		rt.metrics.pushes.WithLabelValues("rejected").Inc()
		rt.log().Debug("ingress_guard: bundle rejected",
			zap.String("reason", res.ack.GetReason()), zap.String("detail", res.ack.GetDetail()))
	}
	writeMessage(w, r, res.status, res.ack)
}

func (rt *runtime) handleStatus(w http.ResponseWriter, r *http.Request) {
	writeMessage(w, r, http.StatusOK, rt.Status())
}

// writeMessage answers in protobuf, or JSON when the client asks for it (curl debugging).
func writeMessage(w http.ResponseWriter, r *http.Request, status int, msg proto.Message) {
	var (
		body []byte
		err  error
		ct   = "application/x-protobuf"
	)
	if strings.Contains(r.Header.Get("Accept"), "application/json") {
		ct = "application/json"
		body, err = protojson.MarshalOptions{EmitUnpopulated: false, Multiline: true}.Marshal(msg)
	} else {
		body, err = proto.Marshal(msg)
	}
	if err != nil {
		http.Error(w, "encode error", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", ct)
	w.WriteHeader(status)
	_, _ = w.Write(body)
}
