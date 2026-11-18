package bundle

import (
	"crypto/ed25519"
	"crypto/rand"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/honest-hosting/caddy-ingress-guard/bundle/bundlepb"
)

type keys struct {
	root     ed25519.PrivateKey
	rootPub  ed25519.PublicKey
	signer   ed25519.PrivateKey
	keyset   *bundlepb.SignedKeyset
	verifier *Verifier
}

func newKeys(t *testing.T) *keys {
	t.Helper()
	rootPub, root, _ := ed25519.GenerateKey(rand.Reader)
	signerPub, signer, _ := ed25519.GenerateKey(rand.Reader)
	now := time.Now()
	sks, err := SignKeyset(&bundlepb.Keyset{KeysetVersion: 1, IssuedAt: now.Unix(), Keys: []*bundlepb.SignerKey{{
		KeyId: "signer-1/v1", Ed25519PublicKey: signerPub,
		NotBefore: now.Add(-time.Hour).Unix(), NotAfter: now.Add(time.Hour).Unix(),
	}}}, Ed25519Signer{ID: "root", Key: root})
	if err != nil {
		t.Fatal(err)
	}
	return &keys{root: root, rootPub: rootPub, signer: signer, keyset: sks,
		verifier: &Verifier{RootKeys: map[string]ed25519.PublicKey{"root": rootPub}}}
}

func (k *keys) build(t *testing.T, target string, seq uint64, ttl time.Duration, rules string) []byte {
	t.Helper()
	sb, err := Build(BuildOptions{
		Target: target, Sequence: seq, ExpiresAt: time.Now().Add(ttl),
		Sections: []SectionInput{{Name: SectionCoraza, Required: true, Body: &bundlepb.CorazaSection{Pre: rules}}},
		Keyset:   k.keyset, Signer: Ed25519Signer{ID: "signer-1/v1", Key: k.signer},
	})
	if err != nil {
		t.Fatal(err)
	}
	raw, err := Marshal(sb)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func open(t *testing.T, k *keys, raw []byte) (*Peeked, error) {
	t.Helper()
	p, err := Peek(raw)
	if err != nil {
		return nil, err
	}
	if _, err := k.verifier.Verify(p); err != nil {
		return nil, err
	}
	if _, err := k.verifier.CheckTime(p, false); err != nil {
		return nil, err
	}
	if _, _, err := OpenPayload(p, map[string]bool{SectionCoraza: true}, "v0.1.0"); err != nil {
		return nil, err
	}
	return p, nil
}

func TestRoundTrip(t *testing.T) {
	k := newKeys(t)
	raw := k.build(t, "site:abc", 42, time.Hour, `SecRule REQUEST_URI "@streq /x" "id:1,deny"`)
	p, err := open(t, k, raw)
	if err != nil {
		t.Fatal(err)
	}
	if p.Manifest.GetSequence() != 42 || p.Manifest.GetTarget() != "site:abc" {
		t.Fatalf("manifest: %v", p.Manifest)
	}
}

func TestDeterministicPayload(t *testing.T) {
	k := newKeys(t)
	a, _ := Peek(k.build(t, "site:abc", 1, time.Hour, "same"))
	b, _ := Peek(k.build(t, "site:abc", 2, time.Hour, "same"))
	if string(a.Manifest.GetPayloadSha256()) != string(b.Manifest.GetPayloadSha256()) {
		t.Fatal("identical content must give identical payload hashes (refresh detection)")
	}
}

func TestRejects(t *testing.T) {
	k := newKeys(t)
	good := k.build(t, "site:abc", 1, time.Hour, "rules")

	mutate := func(fn func(sb *bundlepb.SignedBundle)) []byte {
		sb := &bundlepb.SignedBundle{}
		if err := proto.Unmarshal(good, sb); err != nil {
			t.Fatal(err)
		}
		fn(sb)
		raw, _ := proto.Marshal(sb)
		return raw
	}

	other := newKeys(t)
	cases := map[string]struct {
		raw    []byte
		reason string
	}{
		"garbage":           {[]byte("not a bundle"), ReasonMalformed},
		"tampered manifest": {mutate(func(sb *bundlepb.SignedBundle) { sb.Manifest[len(sb.Manifest)-1] ^= 1 }), ""},
		"tampered payload":  {mutate(func(sb *bundlepb.SignedBundle) { sb.Payload[0] ^= 1 }), ReasonBadPayload},
		"bad signature":     {mutate(func(sb *bundlepb.SignedBundle) { sb.Signature[0] ^= 1 }), ReasonBadSignature},
		"unknown signer":    {mutate(func(sb *bundlepb.SignedBundle) { sb.KeyId = "signer-9/v1" }), ReasonUnknownKey},
		"foreign keyset":    {mutate(func(sb *bundlepb.SignedBundle) { sb.Keyset = other.keyset }), ReasonBadKeyset},
		"expired":           {k.build(t, "site:abc", 2, -time.Minute, "rules"), ReasonExpired},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			_, err := open(t, k, c.raw)
			if err == nil {
				t.Fatal("accepted")
			}
			if c.reason != "" && ReasonOf(err) != c.reason {
				t.Fatalf("reason %q, want %q (%v)", ReasonOf(err), c.reason, err)
			}
		})
	}
}

func TestRequiredSectionTooNew(t *testing.T) {
	k := newKeys(t)
	sb, err := Build(BuildOptions{
		Target: "site:abc", Sequence: 1, ExpiresAt: time.Now().Add(time.Hour),
		Sections: []SectionInput{{Name: "ratelimit", MinModuleVersion: "v9.0.0", Required: true, Body: &bundlepb.CorazaSection{}}},
		Keyset:   k.keyset, Signer: Ed25519Signer{ID: "signer-1/v1", Key: k.signer},
	})
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := Marshal(sb)
	p, _ := Peek(raw)
	if _, _, err := OpenPayload(p, map[string]bool{SectionCoraza: true}, "v0.1.0"); ReasonOf(err) != ReasonUnsupportedSection {
		t.Fatalf("got %v, want unsupported_section", err)
	}
}

func TestNextSequenceMonotonic(t *testing.T) {
	now := time.Now()
	s1 := NextSequence(0, now)
	if s2 := NextSequence(s1, now); s2 != s1+1 {
		t.Fatalf("same instant: %d after %d", s2, s1)
	}
	if s3 := NextSequence(s1+1000, now.Add(-time.Hour)); s3 != s1+1001 {
		t.Fatalf("clock behind: %d", s3)
	}
}
