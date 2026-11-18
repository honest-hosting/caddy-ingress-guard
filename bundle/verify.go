package bundle

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"time"

	"github.com/klauspost/compress/zstd"
	"google.golang.org/protobuf/proto"

	"github.com/honest-hosting/caddy-ingress-guard/bundle/bundlepb"
)

// Peeked is a bundle whose manifest has been parsed but NOT verified. Use it only for the cheap
// rejects (target, sequence); act on nothing until Verifier.Verify succeeds.
type Peeked struct {
	Signed   *bundlepb.SignedBundle
	Manifest *bundlepb.Manifest
}

// Peek applies the size caps and parses the envelope and manifest (verification order steps 1-2).
func Peek(raw []byte) (*Peeked, error) {
	if len(raw) > MaxSignedBundleBytes {
		return nil, reject(ReasonTooLarge, "%d bytes", len(raw))
	}
	sb := &bundlepb.SignedBundle{}
	if err := proto.Unmarshal(raw, sb); err != nil {
		return nil, reject(ReasonMalformed, "bundle: %v", err)
	}
	if len(sb.GetManifest()) == 0 || len(sb.GetManifest()) > MaxManifestBytes {
		return nil, reject(ReasonMalformed, "manifest size %d", len(sb.GetManifest()))
	}
	m := &bundlepb.Manifest{}
	if err := proto.Unmarshal(sb.GetManifest(), m); err != nil {
		return nil, reject(ReasonMalformed, "manifest: %v", err)
	}
	if m.GetFormatVersion() != FormatVersion {
		return nil, reject(ReasonUnsupportedFormat, "format %d", m.GetFormatVersion())
	}
	if !ValidTarget(m.GetTarget()) {
		return nil, reject(ReasonMalformed, "target %q", m.GetTarget())
	}
	return &Peeked{Signed: sb, Manifest: m}, nil
}

// Verifier checks signatures against pinned root keys.
type Verifier struct {
	RootKeys map[string]ed25519.PublicKey // root key ID -> public key
	Now      func() time.Time             // nil: time.Now
}

func (v *Verifier) now() time.Time {
	if v.Now != nil {
		return v.Now()
	}
	return time.Now()
}

// Verify checks the keyset against a pinned root, then the manifest signature against the
// keyset's signer, over the bytes as received (step 3). It returns the parsed keyset.
func (v *Verifier) Verify(p *Peeked) (*bundlepb.Keyset, error) {
	sks := p.Signed.GetKeyset()
	if sks == nil || len(sks.GetKeyset()) == 0 || len(sks.GetKeyset()) > MaxKeysetBytes {
		return nil, reject(ReasonBadKeyset, "missing or oversized keyset")
	}
	root, ok := v.RootKeys[sks.GetRootKeyId()]
	if !ok {
		return nil, reject(ReasonBadKeyset, "unknown root key %q", sks.GetRootKeyId())
	}
	if !ed25519.Verify(root, KeysetSigningInput(sks.GetKeyset()), sks.GetSignature()) {
		return nil, reject(ReasonBadKeyset, "keyset signature")
	}
	ks := &bundlepb.Keyset{}
	if err := proto.Unmarshal(sks.GetKeyset(), ks); err != nil {
		return nil, reject(ReasonBadKeyset, "keyset: %v", err)
	}
	if ks.GetFormatVersion() != FormatVersion {
		return nil, reject(ReasonBadKeyset, "keyset format %d", ks.GetFormatVersion())
	}
	var signer *bundlepb.SignerKey
	for _, k := range ks.GetKeys() {
		if k.GetKeyId() == p.Signed.GetKeyId() {
			signer = k
			break
		}
	}
	if signer == nil || len(signer.GetEd25519PublicKey()) != ed25519.PublicKeySize {
		return nil, reject(ReasonUnknownKey, "signer %q", p.Signed.GetKeyId())
	}
	if !ed25519.Verify(ed25519.PublicKey(signer.GetEd25519PublicKey()),
		ManifestSigningInput(p.Signed.GetManifest()), p.Signed.GetSignature()) {
		return nil, reject(ReasonBadSignature, "manifest signature")
	}
	// The bundle must have been issued inside the signer's validity window.
	issued := p.Manifest.GetIssuedAt()
	if (signer.GetNotBefore() != 0 && issued < signer.GetNotBefore()) ||
		(signer.GetNotAfter() != 0 && issued > signer.GetNotAfter()) {
		return nil, reject(ReasonUnknownKey, "signer %q not valid at issue time", signer.GetKeyId())
	}
	return ks, nil
}

// CheckTime applies not_before and expires_at (step 4). An expired bundle returns expired=true
// with a nil error when allowExpired is set (ingress-tier last-known-good at a fresh start).
func (v *Verifier) CheckTime(p *Peeked, allowExpired bool) (expired bool, err error) {
	now := v.now().Unix()
	if p.Manifest.GetNotBefore() > now {
		return false, reject(ReasonNotYetValid, "not before %d", p.Manifest.GetNotBefore())
	}
	if p.Manifest.GetExpiresAt() <= now {
		if allowExpired {
			return true, nil
		}
		return true, reject(ReasonExpired, "expired at %d", p.Manifest.GetExpiresAt())
	}
	return false, nil
}

var decoder, _ = zstd.NewReader(nil, zstd.WithDecoderMaxMemory(MaxPayloadBytes), zstd.WithDecoderConcurrency(1))

// OpenPayload checks the section headers, the payload hash, then decompresses and parses the
// payload (steps 5-7). Unknown or too-new optional sections are dropped and reported in skipped.
func OpenPayload(p *Peeked, known map[string]bool, moduleVersion string) (payload *bundlepb.Payload, skipped []string, err error) {
	keep := map[string]bool{}
	for _, h := range p.Manifest.GetSections() {
		if SectionSupported(h, known, moduleVersion) {
			keep[h.GetName()] = true
			continue
		}
		if h.GetRequired() {
			return nil, nil, reject(ReasonUnsupportedSection, "%s (min %s)", h.GetName(), h.GetMinModuleVersion())
		}
		skipped = append(skipped, h.GetName())
	}
	if p.Manifest.GetPayloadEncoding() != bundlepb.PayloadEncoding_PAYLOAD_ENCODING_ZSTD {
		return nil, nil, reject(ReasonBadPayload, "encoding %v", p.Manifest.GetPayloadEncoding())
	}
	sum := sha256.Sum256(p.Signed.GetPayload())
	if !bytes.Equal(sum[:], p.Manifest.GetPayloadSha256()) {
		return nil, nil, reject(ReasonBadPayload, "payload hash mismatch")
	}
	if p.Manifest.GetPayloadSize() > MaxPayloadBytes {
		return nil, nil, reject(ReasonBadPayload, "declared size %d over cap", p.Manifest.GetPayloadSize())
	}
	raw, derr := decoder.DecodeAll(p.Signed.GetPayload(), nil)
	if derr != nil {
		return nil, nil, reject(ReasonBadPayload, "decompress: %v", derr)
	}
	if uint64(len(raw)) != p.Manifest.GetPayloadSize() {
		return nil, nil, reject(ReasonBadPayload, "size %d, manifest says %d", len(raw), p.Manifest.GetPayloadSize())
	}
	pl := &bundlepb.Payload{}
	if err := proto.Unmarshal(raw, pl); err != nil {
		return nil, nil, reject(ReasonBadPayload, "payload: %v", err)
	}
	// Keep only sections the manifest declared and this module supports; a payload section the
	// manifest didn't declare is ignored.
	out := &bundlepb.Payload{}
	for _, s := range pl.GetSections() {
		if keep[s.GetName()] {
			out.Sections = append(out.Sections, s)
		}
	}
	return out, skipped, nil
}

// Section returns the named section body from a payload, or nil.
func Section(pl *bundlepb.Payload, name string) []byte {
	for _, s := range pl.GetSections() {
		if s.GetName() == name {
			return s.GetBody()
		}
	}
	return nil
}
