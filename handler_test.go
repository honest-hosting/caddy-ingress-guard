package ingressguard

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/caddyconfig/httpcaddyfile"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"github.com/corazawaf/coraza/v3"
	"github.com/prometheus/client_golang/prometheus"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"go.uber.org/zap/zaptest/observer"
)

// recWriter is the client side of a test request: it records whether anything was written.
type recWriter struct {
	*httptest.ResponseRecorder
	wrote bool
}

func (w *recWriter) WriteHeader(code int) { w.wrote = true; w.ResponseRecorder.WriteHeader(code) }
func (w *recWriter) Write(b []byte) (int, error) {
	w.wrote = true
	return w.ResponseRecorder.Write(b)
}
func (w *recWriter) Flush() { w.wrote = true; w.ResponseRecorder.Flush() }

// served is one request's outcome.
type served struct {
	code   int   // what the client gets: a block error's status, else the written status
	err    error // what the handler returned
	wrote  bool  // anything reached the client writer
	called bool  // next ran
	body   string
	rec    *httptest.ResponseRecorder
	vars   map[string]any
}

func testHandler(app *App, static coraza.WAF) (*Handler, *observer.ObservedLogs) {
	core, logs := observer.New(zapcore.DebugLevel)
	return &Handler{Stage: StageInspect, app: app, logger: zap.NewNop(), events: zap.New(core), static: static}, logs
}

func okHandler(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) }

// run serves req through h as Caddy would (replacer and vars in the context).
func run(t *testing.T, h *Handler, req *http.Request, repl *caddy.Replacer, next http.HandlerFunc) served {
	t.Helper()
	vars := map[string]any{}
	ctx := context.WithValue(req.Context(), caddy.ReplacerCtxKey, repl)
	ctx = context.WithValue(ctx, caddyhttp.VarsCtxKey, vars)
	req = req.WithContext(ctx)
	w := &recWriter{ResponseRecorder: httptest.NewRecorder()}
	res := served{rec: w.ResponseRecorder, vars: vars}
	res.err = h.ServeHTTP(w, req, caddyhttp.HandlerFunc(func(w http.ResponseWriter, r *http.Request) error {
		res.called = true
		if r.Body != nil {
			b, _ := io.ReadAll(r.Body)
			res.body = string(b)
		}
		next(w, r)
		return nil
	}))
	res.wrote = w.wrote
	res.code = w.Code
	if res.err != nil {
		var he caddyhttp.HandlerError
		if !errors.As(res.err, &he) {
			t.Fatalf("handler returned a non-Caddy error: %v", res.err)
		}
		res.code = he.StatusCode
	}
	return res
}

// onlyEvent returns the single WAF event's fields.
func onlyEvent(t *testing.T, logs *observer.ObservedLogs) map[string]any {
	t.Helper()
	evs := logs.FilterMessage(eventMessage).All()
	if len(evs) != 1 {
		t.Fatalf("%d WAF events, want 1", len(evs))
	}
	return evs[0].ContextMap()
}

// metricValue reads one series of a collector (labels nil: the only series).
func metricValue(t *testing.T, c prometheus.Collector, labels map[string]string) float64 {
	t.Helper()
	reg := prometheus.NewRegistry()
	reg.MustRegister(c)
	mfs, err := reg.Gather()
	if err != nil {
		t.Fatal(err)
	}
	for _, mf := range mfs {
	series:
		for _, m := range mf.GetMetric() {
			for _, lp := range m.GetLabel() {
				if want, ok := labels[lp.GetName()]; ok && want != lp.GetValue() {
					continue series
				}
			}
			if g := m.GetGauge(); g != nil {
				return g.GetValue()
			}
			return m.GetCounter().GetValue()
		}
	}
	return 0
}

func staticWAF(t *testing.T, directives string) coraza.WAF {
	t.Helper()
	waf, err := buildStatic(directives, "")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { closeWAF(waf) })
	return waf
}

// A block is a Caddy error (so handle_errors renders it), carrying the rule and the transaction
// ID, and nothing has been written to the client.
func TestBlockReturnsCaddyError(t *testing.T) {
	f := newFixture(t)
	if res := f.rt.Submit(f.bundle(t, "site:s1", probeA)); !res.ack.GetAccepted() {
		t.Fatal(res.ack.GetDetail())
	}
	app := &App{rt: f.rt, Mode: ModeSite, siteID: "s1"}
	h, logs := testHandler(app, nil)
	res := run(t, h, httptest.NewRequest(http.MethodGet, "/__hh_probe_a", nil), caddy.NewReplacer(), okHandler)
	if res.called || res.wrote {
		t.Fatalf("a block must not call next (%v) or write (%v)", res.called, res.wrote)
	}
	var he caddyhttp.HandlerError
	if !errors.As(res.err, &he) || he.StatusCode != http.StatusForbidden {
		t.Fatalf("want a 403 caddyhttp.HandlerError, got %v", res.err)
	}
	var ie *InterruptionError
	if !errors.As(res.err, &ie) || ie.RuleID != 9001 || ie.TxID == "" || he.ID != ie.TxID {
		t.Fatalf("interruption error: %+v (error ID %q)", ie, he.ID)
	}
	ev := onlyEvent(t, logs)
	for k, v := range map[string]any{
		"action": ActionBlock, "mode": ModeSite, "site": "s1", "target": "site:s1",
		"rule_id": int64(9001), "status": int64(403), "tx_id": ie.TxID, "uri": "/__hh_probe_a",
	} {
		if ev[k] != v {
			t.Errorf("event %s = %v (%T), want %v", k, ev[k], ev[k], v)
		}
	}
	if ev["sequence"] != f.seq {
		t.Errorf("event sequence = %v, want %d", ev["sequence"], f.seq)
	}
	if res.vars["ingress_guard.action"] != ActionBlock || res.vars["ingress_guard.rule_id"] != "9001" {
		t.Errorf("vars: %v", res.vars)
	}

	// A request no rule matches writes no event.
	logs.TakeAll()
	if res := run(t, h, httptest.NewRequest(http.MethodGet, "/ok", nil), caddy.NewReplacer(), okHandler); res.code != 200 || res.err != nil {
		t.Fatalf("clean request: %d %v", res.code, res.err)
	}
	if n := logs.Len(); n != 0 {
		t.Fatalf("%d log lines for a clean request", n)
	}
}

// tx_id_header: a well-formed header value is the transaction ID (and the error ID); a malformed
// one is ignored.
func TestTxIDHeader(t *testing.T) {
	f := newFixture(t)
	f.rt.Submit(f.bundle(t, "site:s1", probeA))
	app := &App{rt: f.rt, Mode: ModeSite, TxIDHeader: "X-Request-ID"}
	h, logs := testHandler(app, nil)

	repl := caddy.NewReplacer()
	req := httptest.NewRequest(http.MethodGet, "/__hh_probe_a", nil)
	req.Header.Set("X-Request-ID", "req-0123.abc_D")
	res := run(t, h, req, repl, okHandler)
	var he caddyhttp.HandlerError
	if !errors.As(res.err, &he) || he.ID != "req-0123.abc_D" {
		t.Fatalf("error ID %q, want the header value", he.ID)
	}
	if got, _ := repl.GetString("http.transaction_id"); got != "req-0123.abc_D" {
		t.Errorf("{http.transaction_id} = %q", got)
	}
	if ev := onlyEvent(t, logs); ev["tx_id"] != "req-0123.abc_D" {
		t.Errorf("event tx_id = %v", ev["tx_id"])
	}

	for _, bad := range []string{`a"b`, "with space", strings.Repeat("x", 129)} {
		req := httptest.NewRequest(http.MethodGet, "/__hh_probe_a", nil)
		req.Header.Set("X-Request-ID", bad)
		res := run(t, h, req, caddy.NewReplacer(), okHandler)
		if !errors.As(res.err, &he) || he.ID == "" || he.ID == bad {
			t.Errorf("malformed %q: error ID %q, want a generated one", bad, he.ID)
		}
	}
}

// DR-03: a handler with its own static rules enforces them whatever the app's mode, bundle state
// and force_mode, and logs as mode static.
func TestStaticHandler(t *testing.T) {
	f := newMultiFixture(t)
	app := multiApp(f)
	app.ForceMode = ForceDetect // bundle-driven only: static rules keep enforcing
	h, logs := testHandler(app, staticWAF(t, "SecRuleEngine On\n"+probeA))

	res := run(t, h, httptest.NewRequest(http.MethodGet, "/__hh_probe_a", nil), caddy.NewReplacer(), okHandler)
	if res.code != 403 || res.called || res.wrote {
		t.Fatalf("static block: code %d, called %v, wrote %v", res.code, res.called, res.wrote)
	}
	ev := onlyEvent(t, logs)
	if ev["mode"] != ModeStatic || ev["action"] != ActionBlock {
		t.Fatalf("event: %v", ev)
	}
	for _, k := range []string{"target", "sequence", "profile", "forced"} {
		if _, ok := ev[k]; ok {
			t.Errorf("a static event has no %s", k)
		}
	}
	if res := run(t, h, httptest.NewRequest(http.MethodGet, "/ok", nil), caddy.NewReplacer(), okHandler); res.code != 200 || !res.called {
		t.Fatalf("static pass: code %d", res.code)
	}
	if got := metricValue(t, f.rt.metrics.noIdentity, nil); got != 0 {
		t.Fatalf("a static handler never counts no_identity (got %v)", got)
	}

	if err := h.Cleanup(); err != nil || h.static != nil {
		t.Fatalf("cleanup: %v", err)
	}
	if _, err := buildStatic("SecRule this is not seclang", ""); err == nil {
		t.Fatal("bad static rules must fail provisioning")
	}
}

// A response-header rule (phase 3) blocks before anything reaches the client, and the error page
// doesn't inherit the upstream's headers.
func TestResponseHeaderBlock(t *testing.T) {
	f := newFixture(t)
	rule := `SecRule RESPONSE_HEADERS:X-Leak "@streq yes" "id:9100,phase:3,deny,status:403,log"`
	h, logs := testHandler(&App{rt: f.rt, Mode: ModeSite}, staticWAF(t, "SecRuleEngine On\n"+rule))
	vars := map[string]any{}
	ctx := context.WithValue(context.Background(), caddy.ReplacerCtxKey, caddy.NewReplacer())
	ctx = context.WithValue(ctx, caddyhttp.VarsCtxKey, vars)
	req := httptest.NewRequest(http.MethodGet, "/page", nil).WithContext(ctx)
	w := &recWriter{ResponseRecorder: httptest.NewRecorder()}
	w.Header().Set("X-Before", "1") // set by an earlier handler
	err := h.ServeHTTP(w, req, caddyhttp.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) error {
		w.Header().Set("X-Leak", "yes")
		w.Header().Set("Content-Length", "5")
		w.WriteHeader(http.StatusOK)
		if n, err := w.Write([]byte("hello")); n != 5 || err != nil {
			t.Errorf("a blocked body is discarded quietly: %d %v", n, err)
		}
		return nil
	}))
	var he caddyhttp.HandlerError
	if !errors.As(err, &he) || he.StatusCode != 403 {
		t.Fatalf("want a 403 error, got %v", err)
	}
	if w.wrote {
		t.Fatal("nothing may reach the client on a block")
	}
	if w.Header().Get("X-Leak") != "" || w.Header().Get("Content-Length") != "" || w.Header().Get("X-Before") != "1" {
		t.Fatalf("headers must be back as they were before the WAF: %v", w.Header())
	}
	if ev := onlyEvent(t, logs); ev["rule_id"] != int64(9100) {
		t.Fatalf("event: %v", ev)
	}
}

// Streaming parity: response bodies are never buffered, even when the rules ask for response
// body access; a flush reaches the client while next is still running.
func TestResponseStreams(t *testing.T) {
	f := newFixture(t)
	rules := "SecRuleEngine On\nSecResponseBodyAccess On\nSecResponseBodyMimeType text/plain text/event-stream\n" + probeA
	h, _ := testHandler(&App{rt: f.rt, Mode: ModeSite}, staticWAF(t, rules))
	res := run(t, h, httptest.NewRequest(http.MethodGet, "/events", nil), caddy.NewReplacer(), func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("data: 1\n\n"))
		if err := http.NewResponseController(w).Flush(); err != nil {
			t.Errorf("flush: %v", err)
		}
		rec := w.(interface{ Unwrap() http.ResponseWriter }).Unwrap().(*recWriter)
		if !rec.Flushed || rec.Body.String() != "data: 1\n\n" {
			t.Errorf("the first event must reach the client before next returns (flushed %v, body %q)", rec.Flushed, rec.Body.String())
		}
	})
	if res.code != 200 || res.err != nil {
		t.Fatalf("code %d, err %v", res.code, res.err)
	}
}

func TestAppForceModeValidation(t *testing.T) {
	pub, _, _ := ed25519.GenerateKey(rand.Reader)
	base := func(mode, target string) App {
		return App{Mode: mode, Targets: []string{target}, PushListen: "127.0.0.1:2020",
			RootKeys: map[string]string{"root": base64.StdEncoding.EncodeToString(pub)}}
	}
	for _, c := range []struct {
		name string
		app  App
		ok   bool
	}{
		{"multi: allowed", func() App { a := base(ModeMulti, "ingress:p1"); a.ForceMode = ForceDetect; return a }(), true},
		{"site: refused", func() App { a := base(ModeSite, "site:s1"); a.ForceMode = ForceDetect; return a }(), false},
		{"static: refused", App{Mode: ModeStatic, StaticDirectives: "SecRuleEngine On", ForceMode: ForceDetect}, false},
		{"unknown value", func() App { a := base(ModeMulti, "ingress:p1"); a.ForceMode = "off"; return a }(), false},
		{"tx_id_header ok", func() App { a := base(ModeSite, "site:s1"); a.TxIDHeader = "X-Request-ID"; return a }(), true},
		{"tx_id_header bad", func() App { a := base(ModeSite, "site:s1"); a.TxIDHeader = "X Request"; return a }(), false},
	} {
		_, err := c.app.runtimeConfig()
		if (err == nil) != c.ok {
			t.Errorf("%s: err = %v", c.name, err)
		}
	}
}

func TestCaddyfileOptions(t *testing.T) {
	d := caddyfile.NewTestDispenser(`ingress_guard {
		mode multi
		target ingress:p1
		force_mode detect
		tx_id_header X-Request-ID
		tenant_identity {http.vars.tenant}
	}`)
	v, err := parseGlobalOption(d, nil)
	if err != nil {
		t.Fatal(err)
	}
	var app App
	if err := json.Unmarshal(v.(httpcaddyfile.App).Value, &app); err != nil {
		t.Fatal(err)
	}
	if app.ForceMode != ForceDetect || app.TxIDHeader != "X-Request-ID" || app.TenantIdentity != "{http.vars.tenant}" {
		t.Fatalf("parsed: %+v", app)
	}

	d = caddyfile.NewTestDispenser("ingress_guard_inspect {\n\tstatic_file /etc/waf/rules.conf\n\tstatic_directives \"SecRuleEngine On\"\n}")
	mh, err := parseStage(StageInspect)(httpcaddyfile.Helper{Dispenser: d})
	if err != nil {
		t.Fatal(err)
	}
	if hd := mh.(*Handler); hd.StaticFile != "/etc/waf/rules.conf" || hd.StaticDirectives != "SecRuleEngine On" {
		t.Fatalf("parsed: %+v", hd)
	}

	d = caddyfile.NewTestDispenser("ingress_guard_access {\n\tstatic_file /etc/waf/rules.conf\n}")
	if _, err := parseStage(StageAccess)(httpcaddyfile.Helper{Dispenser: d}); err == nil {
		t.Fatal("the access stage takes no static rules")
	}
}
