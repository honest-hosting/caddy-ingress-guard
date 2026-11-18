package ingressguard

import (
	"crypto/ed25519"
	"crypto/rand"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/corazawaf/coraza/v3"
	corazahttp "github.com/corazawaf/coraza/v3/http"

	"github.com/honest-hosting/caddy-ingress-guard/bundle"
	"github.com/honest-hosting/caddy-ingress-guard/bundle/bundlepb"
)

type fixture struct {
	rt     *runtime
	keyset *bundlepb.SignedKeyset
	signer bundle.Signer
	seq    uint64
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	rootPub, root, _ := ed25519.GenerateKey(rand.Reader)
	signerPub, signer, _ := ed25519.GenerateKey(rand.Reader)
	now := time.Now()
	sks, err := bundle.SignKeyset(&bundlepb.Keyset{KeysetVersion: 1, Keys: []*bundlepb.SignerKey{{
		KeyId: "signer-1/v1", Ed25519PublicKey: signerPub,
		NotBefore: now.Add(-time.Hour).Unix(), NotAfter: now.Add(time.Hour).Unix(),
	}}}, bundle.Ed25519Signer{ID: "root", Key: root})
	if err != nil {
		t.Fatal(err)
	}
	rt := newRuntime()
	rt.configure(&runtimeConfig{
		mode:     ModeSite,
		targets:  map[string]bool{"layer:global": true, "site:s1": true},
		verifier: &bundle.Verifier{RootKeys: map[string]ed25519.PublicKey{"root": rootPub}},
	})
	return &fixture{rt: rt, keyset: sks, signer: bundle.Ed25519Signer{ID: "signer-1/v1", Key: signer}}
}

func (f *fixture) bundle(t *testing.T, target, pre string, constraints ...*bundlepb.LayerConstraint) []byte {
	t.Helper()
	f.seq = bundle.NextSequence(f.seq, time.Now())
	sb, err := bundle.Build(bundle.BuildOptions{
		Target: target, Sequence: f.seq, ExpiresAt: time.Now().Add(time.Hour),
		Sections: []bundle.SectionInput{
			{Name: bundle.SectionCoraza, Required: true, Body: &bundlepb.CorazaSection{Pre: pre}},
			{Name: bundle.SectionSwitches, Required: true, Body: &bundlepb.SwitchesSection{Mode: bundlepb.Mode_MODE_ENFORCE}},
		},
		LayerConstraints: constraints,
		Keyset:           f.keyset, Signer: f.signer,
	})
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := bundle.Marshal(sb)
	return raw
}

const (
	probeA = `SecRule REQUEST_URI "@beginsWith /__hh_probe_a" "id:9001,phase:1,deny,status:403"`
	probeB = `SecRule REQUEST_URI "@beginsWith /__hh_probe_b" "id:9002,phase:1,deny,status:403"`
)

func status(t *testing.T, waf coraza.WAF, path string) int {
	t.Helper()
	rec := httptest.NewRecorder()
	corazahttp.WrapHandler(waf, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})).ServeHTTP(rec, httptest.NewRequest(http.MethodGet, path, nil))
	return rec.Code
}

func TestSwapAlternatingProbes(t *testing.T) {
	f := newFixture(t)
	if !f.rt.snapshot().unprotected() {
		t.Fatal("must start unprotected (open)")
	}
	for i, c := range []struct{ pre, blocked, allowed string }{
		{probeA, "/__hh_probe_a", "/__hh_probe_b"},
		{probeB, "/__hh_probe_b", "/__hh_probe_a"},
		{probeA, "/__hh_probe_a", "/__hh_probe_b"},
	} {
		res := f.rt.Submit(f.bundle(t, "site:s1", c.pre))
		if !res.ack.GetAccepted() {
			t.Fatalf("push %d rejected: %s", i, res.ack.GetDetail())
		}
		waf := f.rt.snapshot().waf
		if got := status(t, waf, c.blocked); got != http.StatusForbidden {
			t.Fatalf("push %d: %s got %d, want 403", i, c.blocked, got)
		}
		if got := status(t, waf, c.allowed); got != http.StatusOK {
			t.Fatalf("push %d: %s got %d, want 200", i, c.allowed, got)
		}
	}
}

func TestRejectsKeepActive(t *testing.T) {
	f := newFixture(t)
	first := f.bundle(t, "site:s1", probeA)
	if res := f.rt.Submit(first); !res.ack.GetAccepted() {
		t.Fatal(res.ack.GetDetail())
	}
	active := f.rt.snapshot()

	if res := f.rt.Submit(first); res.ack.GetReason() != bundle.ReasonOldSequence {
		t.Fatalf("replay: %q", res.ack.GetReason())
	}
	if res := f.rt.Submit(f.bundle(t, "site:other", probeB)); res.ack.GetReason() != bundle.ReasonWrongTarget {
		t.Fatalf("wrong target: %q", res.ack.GetReason())
	}
	if res := f.rt.Submit(f.bundle(t, "site:s1", "SecRule this is not seclang")); res.ack.GetReason() != bundle.ReasonBuildFailed {
		t.Fatalf("bad rules: %q", res.ack.GetReason())
	}
	if f.rt.snapshot() != active {
		t.Fatal("a rejected push must leave the active snapshot untouched")
	}
}

func TestRefreshDoesNotRebuild(t *testing.T) {
	f := newFixture(t)
	f.rt.Submit(f.bundle(t, "site:s1", probeA))
	before := f.rt.snapshot()
	res := f.rt.Submit(f.bundle(t, "site:s1", probeA)) // same content, new sequence
	if !res.ack.GetAccepted() {
		t.Fatal(res.ack.GetDetail())
	}
	after := f.rt.snapshot()
	if after.waf != before.waf {
		t.Fatal("unchanged content must keep the built WAF instance")
	}
	if after.layers["site:s1"].manifest.GetSequence() <= before.layers["site:s1"].manifest.GetSequence() {
		t.Fatal("refresh must advance the sequence")
	}
}

func TestPendingLayer(t *testing.T) {
	f := newFixture(t)
	need := &bundlepb.LayerConstraint{Target: "layer:global", MinSequence: 1}
	res := f.rt.Submit(f.bundle(t, "site:s1", probeA, need))
	if !res.ack.GetAccepted() || f.rt.snapshot().pending["site:s1"] == nil {
		t.Fatalf("site bundle should wait for layer:global: %v", res.ack)
	}
	if f.rt.snapshot().waf != nil {
		t.Fatal("nothing should be active yet")
	}
	if res := f.rt.Submit(f.bundle(t, "layer:global", probeB)); !res.ack.GetAccepted() {
		t.Fatal(res.ack.GetDetail())
	}
	s := f.rt.snapshot()
	if s.pending["site:s1"] != nil || s.layers["site:s1"] == nil {
		t.Fatal("global layer should release the pending site bundle")
	}
	if status(t, s.waf, "/__hh_probe_a") != http.StatusForbidden || status(t, s.waf, "/__hh_probe_b") != http.StatusForbidden {
		t.Fatal("both layers' rules should be active")
	}
}
