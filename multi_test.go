package ingressguard

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/caddyserver/caddy/v2"

	"github.com/honest-hosting/caddy-ingress-guard/bundle"
	"github.com/honest-hosting/caddy-ingress-guard/bundle/bundlepb"
)

func newMultiFixture(t *testing.T) *fixture {
	t.Helper()
	f := newFixture(t)
	cfg := *f.rt.cfg.Load()
	cfg.mode = ModeMulti
	cfg.targets = map[string]bool{"ingress:p1": true}
	f.rt.configure(&cfg)
	return f
}

func (f *fixture) signed(t *testing.T, target string, sections ...bundle.SectionInput) []byte {
	t.Helper()
	f.seq = bundle.NextSequence(f.seq, time.Now())
	sb, err := bundle.Build(bundle.BuildOptions{
		Target: target, Sequence: f.seq, ExpiresAt: time.Now().Add(time.Hour),
		Sections: sections, Keyset: f.keyset, Signer: f.signer,
	})
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := bundle.Marshal(sb)
	return raw
}

// ingressBundle: probe A is blocked in the post slot; site-b's host rule removes that rule for
// site-b only. Profiles: enforce (default), detect, off.
func (f *fixture) ingressBundle(t *testing.T, poolMode bundlepb.Mode, defaultProfile string) []byte {
	t.Helper()
	exclusion := `SecRule REQUEST_HEADERS:` + bundle.SiteHeader + ` "@pm site-b" "id:20000001,phase:1,pass,nolog,ctl:ruleRemoveById=9001"`
	return f.signed(t, "ingress:p1",
		bundle.SectionInput{Name: bundle.SectionCoraza, Required: true, Body: &bundlepb.CorazaSection{Post: probeA}},
		bundle.SectionInput{Name: bundle.SectionSwitches, Required: true, Body: &bundlepb.SwitchesSection{Mode: poolMode}},
		bundle.SectionInput{Name: bundle.SectionProfiles, Required: true, Body: &bundlepb.ProfilesSection{
			Profiles: []*bundlepb.Profile{
				{Name: "enforce", HostRules: exclusion},
				{Name: "detect", Mode: bundlepb.Mode_MODE_DETECT},
				{Name: "off", Mode: bundlepb.Mode_MODE_OFF},
			},
			DefaultProfile: defaultProfile,
			Sites:          map[string]string{"site-a": "enforce", "site-b": "enforce", "site-d": "detect", "site-o": "off"},
		}},
	)
}

func multiApp(f *fixture) *App {
	return &App{rt: f.rt, Mode: ModeMulti, SiteIdentity: "{hh_site}", TenantIdentity: "{hh_tenant}"}
}

// serve runs one request through the inspect handler as Caddy would, with site as the route's
// identity ("" for none) and forged as a client-sent site header ("" for none). It returns the
// status the client gets: a block's Caddy error status, else what was written.
func serve(t *testing.T, f *fixture, site, forged string) int {
	t.Helper()
	return serveApp(t, multiApp(f), site, forged).code
}

func serveApp(t *testing.T, app *App, site, forged string) served {
	t.Helper()
	h, _ := testHandler(app, nil)
	repl := caddy.NewReplacer()
	if site != "" {
		repl.Set("hh_site", site)
	}
	req := httptest.NewRequest(http.MethodGet, "/__hh_probe_a", nil)
	if forged != "" {
		req.Header.Set(bundle.SiteHeader, forged)
	}
	return run(t, h, req, repl, func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get(bundle.SiteHeader) != "" {
			t.Error("the site header must not be forwarded")
		}
		w.WriteHeader(http.StatusOK)
	})
}

func TestMultiProfiles(t *testing.T) {
	f := newMultiFixture(t)
	if res := f.rt.Submit(f.ingressBundle(t, bundlepb.Mode_MODE_ENFORCE, "enforce")); !res.ack.GetAccepted() {
		t.Fatal(res.ack.GetDetail())
	}
	for _, c := range []struct {
		name, site, forged string
		want               int
	}{
		{"enforce profile", "site-a", "", 403},
		{"per-site exclusion", "site-b", "", 200},
		{"detect profile", "site-d", "", 200},
		{"off profile", "site-o", "", 200},
		{"unknown site: default profile", "site-new", "", 403},
		{"no identity: passed through (static rules' job)", "", "", 200},
		{"forged header, other site", "site-a", "site-b", 403},
		{"forged header, no identity", "", "site-b", 200},
	} {
		if got := serve(t, f, c.site, c.forged); got != c.want {
			t.Errorf("%s: got %d, want %d", c.name, got, c.want)
		}
	}
}

// D11, FR-18: a multi-mode request without a site identity is never put on the default profile;
// it passes through uninspected and is counted, whatever the snapshot holds.
func TestMultiNoIdentityPassThrough(t *testing.T) {
	f := newMultiFixture(t)
	before := metricValue(t, f.rt.metrics.noIdentity, nil)
	if res := serveApp(t, multiApp(f), "", ""); res.code != 200 || !res.called {
		t.Fatalf("before any bundle: code %d, next called %v", res.code, res.called)
	}
	f.rt.Submit(f.ingressBundle(t, bundlepb.Mode_MODE_ENFORCE, "enforce"))
	res := serveApp(t, multiApp(f), "", "site-b")
	if res.code != 200 || !res.called || res.err != nil {
		t.Fatalf("no identity: code %d, err %v", res.code, res.err)
	}
	if got := metricValue(t, f.rt.metrics.noIdentity, nil) - before; got != 2 {
		t.Fatalf("no_identity_total grew by %v, want 2", got)
	}
	if got := metricValue(t, f.rt.metrics.requests, map[string]string{"result": "no_identity"}); got != 2 {
		t.Fatalf(`requests_total{result="no_identity"} = %v, want 2`, got)
	}
}

// A detect profile serves the request and logs what it would have blocked: the shadow signal.
func TestMultiDetectProfileLogsWouldBlock(t *testing.T) {
	f := newMultiFixture(t)
	f.rt.Submit(f.ingressBundle(t, bundlepb.Mode_MODE_ENFORCE, "enforce"))
	h, logs := testHandler(multiApp(f), nil)
	repl := caddy.NewReplacer()
	repl.Set("hh_site", "site-d")
	repl.Set("hh_tenant", "tenant-1")
	res := run(t, h, httptest.NewRequest(http.MethodGet, "/__hh_probe_a", nil), repl, okHandler)
	if res.code != 200 || !res.called {
		t.Fatalf("detect profile must serve: code %d", res.code)
	}
	ev := onlyEvent(t, logs)
	want := map[string]any{
		"action": ActionWouldBlock, "mode": ModeMulti, "profile": "detect", "site": "site-d",
		"tenant": "tenant-1", "target": "ingress:p1", "rule_id": int64(9001), "status": int64(403),
	}
	for k, v := range want {
		if ev[k] != v {
			t.Errorf("event %s = %v (%T), want %v", k, ev[k], ev[k], v)
		}
	}
	if _, ok := ev["forced"]; ok {
		t.Error("a detect profile's would_block is not forced")
	}
	if res.vars["ingress_guard.action"] != ActionWouldBlock {
		t.Errorf("var ingress_guard.action = %v", res.vars["ingress_guard.action"])
	}
	if got := metricValue(t, f.rt.metrics.interruptions, map[string]string{"action": ActionWouldBlock, "mode": ModeMulti, "profile": "detect"}); got != 1 {
		t.Errorf("interruptions_total{would_block,multi,detect} = %v, want 1", got)
	}
}

// force_mode detect (break-glass c): an enforcing profile serves the request; the event says what
// was not blocked.
func TestForceModeDetect(t *testing.T) {
	f := newMultiFixture(t)
	f.rt.Submit(f.ingressBundle(t, bundlepb.Mode_MODE_ENFORCE, "enforce"))
	app := multiApp(f)
	if got := serveApp(t, app, "site-a", "").code; got != 403 {
		t.Fatalf("without force_mode the enforce profile blocks: got %d", got)
	}
	app.ForceMode = ForceDetect
	h, logs := testHandler(app, nil)
	repl := caddy.NewReplacer()
	repl.Set("hh_site", "site-a")
	res := run(t, h, httptest.NewRequest(http.MethodGet, "/__hh_probe_a", nil), repl, okHandler)
	if res.code != 200 || !res.called || res.err != nil {
		t.Fatalf("force_mode detect must serve: code %d, err %v", res.code, res.err)
	}
	ev := onlyEvent(t, logs)
	if ev["action"] != ActionWouldBlock || ev["forced"] != true || ev["rule_id"] != int64(9001) || ev["profile"] != "enforce" {
		t.Fatalf("event: %v", ev)
	}
}

// Under force_mode, a request interrupted while its body was read still reaches next with its
// whole body.
func TestForceModeKeepsRequestBody(t *testing.T) {
	f := newMultiFixture(t)
	bodyRule := `SecRule ARGS_POST:x "@streq evil" "id:9003,phase:2,deny,status:403,log,msg:'body probe'"`
	f.rt.Submit(f.signed(t, "ingress:p1",
		bundle.SectionInput{Name: bundle.SectionCoraza, Required: true, Body: &bundlepb.CorazaSection{Post: bodyRule}},
		bundle.SectionInput{Name: bundle.SectionProfiles, Required: true, Body: &bundlepb.ProfilesSection{
			Profiles: []*bundlepb.Profile{{Name: "enforce"}}, DefaultProfile: "enforce",
		}},
	))
	body := "x=evil&pad=" + strings.Repeat("a", 4096)
	newReq := func() *http.Request {
		req := httptest.NewRequest(http.MethodPost, "/form", strings.NewReader(body))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		return req
	}
	repl := caddy.NewReplacer()
	repl.Set("hh_site", "site-a")

	h, _ := testHandler(multiApp(f), nil)
	if res := run(t, h, newReq(), repl, okHandler); res.code != 403 || res.called {
		t.Fatalf("enforcing: code %d, next called %v", res.code, res.called)
	}
	app := multiApp(f)
	app.ForceMode = ForceDetect
	h, logs := testHandler(app, nil)
	res := run(t, h, newReq(), repl, okHandler)
	if res.code != 200 || res.body != body {
		t.Fatalf("forced: code %d, upstream got %d of %d body bytes", res.code, len(res.body), len(body))
	}
	if ev := onlyEvent(t, logs); ev["rule_id"] != int64(9003) || ev["message"] != "body probe" {
		t.Fatalf("event: %v", ev)
	}
}

func TestMultiPoolMode(t *testing.T) {
	f := newMultiFixture(t)
	f.rt.Submit(f.ingressBundle(t, bundlepb.Mode_MODE_DETECT, "enforce"))
	if got := serve(t, f, "site-a", ""); got != 200 {
		t.Fatalf("pool-wide detect: got %d, want 200", got)
	}
	f.rt.Submit(f.ingressBundle(t, bundlepb.Mode_MODE_OFF, "enforce"))
	if s := f.rt.snapshot(); !s.off || s.multi != nil || s.unprotected() {
		t.Fatal("pool-wide off: deliberately open, not unprotected")
	}
}

func TestMultiBadProfilesKeepActive(t *testing.T) {
	f := newMultiFixture(t)
	f.rt.Submit(f.ingressBundle(t, bundlepb.Mode_MODE_ENFORCE, "enforce"))
	active := f.rt.snapshot()
	if res := f.rt.Submit(f.ingressBundle(t, bundlepb.Mode_MODE_ENFORCE, "missing")); res.ack.GetReason() != bundle.ReasonBuildFailed {
		t.Fatalf("undefined default profile: %q", res.ack.GetReason())
	}
	if f.rt.snapshot() != active {
		t.Fatal("a rejected push must leave the active profiles untouched")
	}
}
