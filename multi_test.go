package ingressguard

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"go.uber.org/zap"

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

// serve runs one request through the inspect handler as Caddy would, with site as the route's
// identity ("" for none) and forged as a client-sent site header ("" for none).
func serve(t *testing.T, f *fixture, site, forged string) int {
	t.Helper()
	h := &Handler{Stage: StageInspect, app: &App{rt: f.rt, SiteIdentity: "{hh_site}"}, logger: zap.NewNop()}
	repl := caddy.NewReplacer()
	if site != "" {
		repl.Set("hh_site", site)
	}
	req := httptest.NewRequest(http.MethodGet, "/__hh_probe_a", nil)
	if forged != "" {
		req.Header.Set(bundle.SiteHeader, forged)
	}
	req = req.WithContext(context.WithValue(req.Context(), caddy.ReplacerCtxKey, repl))
	rec := httptest.NewRecorder()
	next := caddyhttp.HandlerFunc(func(w http.ResponseWriter, r *http.Request) error {
		if r.Header.Get(bundle.SiteHeader) != "" {
			t.Error("the site header must not be forwarded")
		}
		w.WriteHeader(http.StatusOK)
		return nil
	})
	if err := h.ServeHTTP(rec, req, next); err != nil {
		t.Fatal(err)
	}
	return rec.Code
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
		{"no identity: default profile", "", "", 403},
		{"forged header, other site", "site-a", "site-b", 403},
		{"forged header, no identity", "", "site-b", 403},
	} {
		if got := serve(t, f, c.site, c.forged); got != c.want {
			t.Errorf("%s: got %d, want %d", c.name, got, c.want)
		}
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
