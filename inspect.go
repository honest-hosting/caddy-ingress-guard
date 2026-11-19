package ingressguard

import (
	"bufio"
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"maps"
	"net"
	"net/http"
	"strconv"
	"strings"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"github.com/corazawaf/coraza/v3"
	"github.com/corazawaf/coraza/v3/experimental"
	"github.com/corazawaf/coraza/v3/types"

	"github.com/honest-hosting/caddy-ingress-guard/bundle"
)

// inspection is what the handler selected for one request.
type inspection struct {
	waf     coraza.WAF
	mode    string    // static, multi or site: what drives this request's rules
	profile string    // multi mode
	site    string    // multi mode: the route's identity; site mode: the site's UUID
	snap    *snapshot // bundle-driven modes: the snapshot the WAF came from
	forced  bool      // force_mode detect: interruptions are logged, never enforced
}

// InterruptionError is the error inside the caddyhttp.HandlerError a block returns, so
// handle_errors can render the response ({http.error.status_code}, {http.error.id} = TxID).
type InterruptionError struct {
	RuleID int    // the rule that interrupted the transaction
	Action string // Coraza's interruption action: deny, drop, redirect
	TxID   string // the WAF transaction ID
}

func (e *InterruptionError) Error() string {
	return fmt.Sprintf("ingress_guard: request blocked by rule %d (tx %s)", e.RuleID, e.TxID)
}

// blockError turns an interruption into the error Caddy's handle_errors routes see. Nothing has
// been written to the response when it is returned. An interruption status outside 4xx/5xx
// (redirect, or a deny without one) becomes 403.
func blockError(it *types.Interruption, txID string) error {
	he := caddyhttp.Error(interruptionStatus(it), &InterruptionError{RuleID: it.RuleID, Action: it.Action, TxID: txID})
	he.ID = txID
	return he
}

func interruptionStatus(it *types.Interruption) int {
	if it.Status >= 400 && it.Status <= 599 {
		return it.Status
	}
	return http.StatusForbidden
}

// inspect runs one transaction around next. A block returns a Caddy error instead of writing the
// response, so the server's handle_errors routes render it. Response bodies are never buffered:
// only the response headers are inspected, and the body streams straight through.
func (h *Handler) inspect(w http.ResponseWriter, r *http.Request, next caddyhttp.Handler, in *inspection, nextCalled *bool) error {
	id := h.txID(r)
	tx := newTransaction(in.waf, r.Context(), id)
	defer func() {
		tx.ProcessLogging()
		h.report(r, tx, in)
		_ = tx.Close()
	}()
	if tx.IsRuleEngineOff() {
		*nextCalled = true
		return next.ServeHTTP(w, r)
	}
	if in.mode == ModeMulti && in.site != "" {
		// The identity exists only inside the transaction; the client's copy was removed.
		tx.AddRequestHeader(bundle.SiteHeader, in.site)
	}
	if repl, ok := r.Context().Value(caddy.ReplacerCtxKey).(*caddy.Replacer); ok {
		repl.Set("http.transaction_id", id) // as coraza-caddy sets it, for access logs
	}

	it, err := processRequest(tx, r)
	if err != nil {
		status := http.StatusInternalServerError
		var tooBig *http.MaxBytesError
		if errors.As(err, &tooBig) {
			status = http.StatusRequestEntityTooLarge
		}
		he := caddyhttp.Error(status, fmt.Errorf("ingress_guard: reading request: %w", err))
		he.ID = id
		return he
	}
	if it != nil {
		if !in.forced {
			return blockError(it, id)
		}
		// force_mode detect: logged as would_block (report); serve as if nothing matched. The
		// transaction is interrupted, so the response phases have nothing left to evaluate.
		*nextCalled = true
		return next.ServeHTTP(w, r)
	}

	rw := &respWriter{
		ResponseWriterWrapper: &caddyhttp.ResponseWriterWrapper{ResponseWriter: w},
		tx:                    tx,
		proto:                 r.Proto,
		forced:                in.forced,
		before:                w.Header().Clone(),
	}
	*nextCalled = true
	err = next.ServeHTTP(rw, r)
	if rw.blocked != nil {
		return blockError(rw.blocked, id) // nothing reached the client: see respWriter
	}
	return err
}

// newTransaction starts a transaction with the given ID and the request's context.
func newTransaction(waf coraza.WAF, ctx context.Context, id string) types.Transaction {
	if wo, ok := waf.(experimental.WAFWithOptions); ok {
		return wo.NewTransactionWithOptions(experimental.Options{ID: id, Context: ctx})
	}
	return waf.NewTransactionWithID(id)
}

// txID is the transaction ID: the tx_id_header value if it is well formed, else Caddy's request
// UUID, else a random ID.
func (h *Handler) txID(r *http.Request) string {
	if name := h.app.TxIDHeader; name != "" {
		if v := strings.TrimSpace(r.Header.Get(name)); validTxID(v) {
			return v
		}
	}
	if id := requestUUID(r); id != "" {
		return id
	}
	return rand.Text()
}

// requestUUID is Caddy's {http.request.uuid} (generated on first use), or "" outside an HTTP
// server.
func requestUUID(r *http.Request) string {
	repl, ok := r.Context().Value(caddy.ReplacerCtxKey).(*caddy.Replacer)
	if !ok {
		return ""
	}
	id, _ := repl.GetString("http.request.uuid")
	return id
}

// validTxID accepts a header-supplied transaction ID only if it is short and uses a conservative
// character set: it ends up in log lines, error IDs and (with an audit log) file names.
func validTxID(s string) bool {
	if s == "" || len(s) > 128 {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9', c == '-', c == '_', c == '.':
		default:
			return false
		}
	}
	return true
}

// clientIP is Caddy's client IP (which honours the server's trusted_proxies) when set, else the
// connection's peer address.
func clientIP(r *http.Request) (string, int) {
	addr := r.RemoteAddr
	if v, ok := caddyhttp.GetVar(r.Context(), caddyhttp.ClientIPVarKey).(string); ok && v != "" {
		addr = v
	}
	if host, port, err := net.SplitHostPort(addr); err == nil {
		p, _ := strconv.Atoi(port)
		return host, p
	}
	return addr, 0
}

// processRequest feeds the request to the transaction (phases 1 and 2) and returns the
// interruption, if any. A request body the rules read is put back in front of whatever was not
// read, so next sees the whole body (also when force_mode serves an interrupted request).
func processRequest(tx types.Transaction, r *http.Request) (*types.Interruption, error) {
	client, port := clientIP(r)
	tx.ProcessConnection(client, port, "", 0)
	tx.ProcessURI(r.URL.String(), r.Method, r.Proto)
	for k, vs := range r.Header {
		for _, v := range vs {
			tx.AddRequestHeader(k, v)
		}
	}
	if r.Host != "" {
		// net/http moves Host out of the header map.
		tx.AddRequestHeader("Host", r.Host)
		name := r.Host
		if h, _, err := net.SplitHostPort(r.Host); err == nil {
			name = h
		}
		tx.SetServerName(name)
	}
	// net/http removes Transfer-Encoding too; smuggling rules (e.g. CRS 920171) need every value.
	for _, te := range r.TransferEncoding {
		tx.AddRequestHeader("Transfer-Encoding", te)
	}
	if it := tx.ProcessRequestHeaders(); it != nil {
		return it, nil
	}

	if tx.IsRequestBodyAccessible() && r.Body != nil && r.Body != http.NoBody {
		it, _, err := tx.ReadRequestBodyFrom(r.Body)
		if err != nil {
			return nil, err
		}
		read, err := tx.RequestBodyReader()
		if err != nil {
			return nil, err
		}
		r.Body = readCloser{Reader: io.MultiReader(read, r.Body), Closer: r.Body}
		if it != nil {
			return it, nil
		}
	}
	return tx.ProcessRequestBody()
}

type readCloser struct {
	io.Reader
	io.Closer
}

var errBlockedResponse = errors.New("ingress_guard: response blocked")

// respWriter inspects the response headers (phase 3) when the final status is written, and never
// buffers the body: a streamed response (SSE, chunked, flushed) passes straight through.
//
// On a block, nothing reaches the client: the status is not forwarded, the body is discarded, a
// hijack is refused, and the response headers are put back as they were when the WAF handed over
// (so an upstream's Content-Length or cookies don't leak into the error page). The handler then
// returns the block as a Caddy error. Flush and Hijack are reached through
// http.ResponseController via Unwrap, like any Caddy response writer wrapper.
type respWriter struct {
	*caddyhttp.ResponseWriterWrapper
	tx          types.Transaction
	proto       string
	forced      bool
	before      http.Header
	wroteHeader bool
	blocked     *types.Interruption
}

func (w *respWriter) WriteHeader(code int) {
	switch {
	case w.blocked != nil:
		return
	case w.wroteHeader:
		w.ResponseWriter.WriteHeader(code) // superfluous: net/http reports it
		return
	case code >= 100 && code < 200 && code != http.StatusSwitchingProtocols:
		w.ResponseWriter.WriteHeader(code) // informational, e.g. 103 Early Hints
		return
	}
	w.wroteHeader = true
	for k, vs := range w.Header() {
		for _, v := range vs {
			w.tx.AddResponseHeader(k, v)
		}
	}
	if it := w.tx.ProcessResponseHeaders(code, w.proto); it != nil && !w.forced {
		w.blocked = it
		hdr := w.ResponseWriter.Header()
		clear(hdr)
		maps.Copy(hdr, w.before)
		return
	}
	w.ResponseWriter.WriteHeader(code)
}

func (w *respWriter) Write(b []byte) (int, error) {
	if !w.wroteHeader {
		w.WriteHeader(http.StatusOK)
	}
	if w.blocked != nil {
		return len(b), nil
	}
	return w.ResponseWriter.Write(b)
}

// ReadFrom keeps the fast path (e.g. sendfile) once the headers have passed.
func (w *respWriter) ReadFrom(src io.Reader) (int64, error) {
	if !w.wroteHeader {
		w.WriteHeader(http.StatusOK)
	}
	if w.blocked != nil {
		return io.Copy(io.Discard, src)
	}
	return w.ResponseWriterWrapper.ReadFrom(src)
}

// FlushError is what http.ResponseController.Flush calls.
func (w *respWriter) FlushError() error {
	if !w.wroteHeader {
		w.WriteHeader(http.StatusOK)
	}
	if w.blocked != nil {
		return nil
	}
	return http.NewResponseController(w.ResponseWriter).Flush()
}

// Flush implements http.Flusher for handlers that assert it directly.
func (w *respWriter) Flush() { _ = w.FlushError() }

// Hijack hands the connection over (e.g. after a 101), unless the response was blocked.
func (w *respWriter) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	if w.blocked != nil {
		return nil, nil, errBlockedResponse
	}
	return http.NewResponseController(w.ResponseWriter).Hijack()
}

var (
	_ http.Flusher  = (*respWriter)(nil)
	_ http.Hijacker = (*respWriter)(nil)
	_ io.ReaderFrom = (*respWriter)(nil)
)
