package bundle

import (
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
	"time"

	"github.com/klauspost/compress/zstd"
	"google.golang.org/protobuf/proto"

	"github.com/honest-hosting/caddy-ingress-guard/bundle/bundlepb"
)

// deterministic marshaling: identical content gives identical bytes, so an unchanged refresh
// keeps its payload_sha256.
var marshal = proto.MarshalOptions{Deterministic: true}

// SectionInput is one payload section for Build.
type SectionInput struct {
	Name             string
	MinModuleVersion string
	Required         bool
	Body             proto.Message
}

// BuildOptions describes one bundle.
type BuildOptions struct {
	Target           string
	Sequence         uint64
	IssuedAt         time.Time // zero: now
	NotBefore        time.Time // zero: IssuedAt
	ExpiresAt        time.Time // required
	Sections         []SectionInput
	LayerConstraints []*bundlepb.LayerConstraint
	Lineage          []*bundlepb.LineageEntry
	ParentSequence   uint64
	CRSVersion       string
	Keyset           *bundlepb.SignedKeyset
	Signer           Signer
}

// NextSequence returns the next sequence for a target: unix microseconds, or prev+1 if the clock
// hasn't moved past prev. It never goes backwards, even after a database restore.
func NextSequence(prev uint64, now time.Time) uint64 {
	us := uint64(now.UnixMicro())
	if us > prev {
		return us
	}
	return prev + 1
}

// Build marshals, compresses and signs a bundle.
func Build(o BuildOptions) (*bundlepb.SignedBundle, error) {
	if !ValidTarget(o.Target) {
		return nil, fmt.Errorf("invalid target %q", o.Target)
	}
	if o.Signer == nil || o.Keyset == nil {
		return nil, errors.New("signer and keyset are required")
	}
	if o.Sequence == 0 {
		return nil, errors.New("sequence is required")
	}
	if o.ExpiresAt.IsZero() {
		return nil, errors.New("expiry is required")
	}
	issued := o.IssuedAt
	if issued.IsZero() {
		issued = time.Now()
	}
	notBefore := o.NotBefore
	if notBefore.IsZero() {
		notBefore = issued
	}

	payload := &bundlepb.Payload{}
	headers := make([]*bundlepb.SectionHeader, 0, len(o.Sections))
	for _, s := range o.Sections {
		body, err := marshal.Marshal(s.Body)
		if err != nil {
			return nil, fmt.Errorf("section %s: %w", s.Name, err)
		}
		payload.Sections = append(payload.Sections, &bundlepb.Section{Name: s.Name, Body: body})
		headers = append(headers, &bundlepb.SectionHeader{
			Name: s.Name, MinModuleVersion: s.MinModuleVersion, Required: s.Required,
		})
	}
	raw, err := marshal.Marshal(payload)
	if err != nil {
		return nil, err
	}
	if len(raw) > MaxPayloadBytes {
		return nil, fmt.Errorf("payload %d bytes exceeds %d", len(raw), MaxPayloadBytes)
	}
	enc, err := zstd.NewWriter(nil, zstd.WithEncoderLevel(zstd.SpeedBetterCompression))
	if err != nil {
		return nil, err
	}
	compressed := enc.EncodeAll(raw, nil)
	_ = enc.Close()
	sum := sha256.Sum256(compressed)

	m := &bundlepb.Manifest{
		FormatVersion:    FormatVersion,
		BundleId:         newUUIDv7(issued),
		Target:           o.Target,
		Sequence:         o.Sequence,
		IssuedAt:         issued.Unix(),
		NotBefore:        notBefore.Unix(),
		ExpiresAt:        o.ExpiresAt.Unix(),
		PayloadSha256:    sum[:],
		PayloadEncoding:  bundlepb.PayloadEncoding_PAYLOAD_ENCODING_ZSTD,
		PayloadSize:      uint64(len(raw)),
		Sections:         headers,
		LayerConstraints: o.LayerConstraints,
		Lineage:          o.Lineage,
		ParentSequence:   o.ParentSequence,
		CrsVersion:       o.CRSVersion,
	}
	mb, err := marshal.Marshal(m)
	if err != nil {
		return nil, err
	}
	if len(mb) > MaxManifestBytes {
		return nil, fmt.Errorf("manifest %d bytes exceeds %d", len(mb), MaxManifestBytes)
	}
	sig, err := o.Signer.Sign(ManifestSigningInput(mb))
	if err != nil {
		return nil, fmt.Errorf("sign manifest: %w", err)
	}
	return &bundlepb.SignedBundle{
		Manifest:  mb,
		Signature: sig,
		KeyId:     o.Signer.KeyID(),
		Payload:   compressed,
		Keyset:    o.Keyset,
	}, nil
}

// SignKeyset signs a keyset with the root key.
func SignKeyset(ks *bundlepb.Keyset, root Signer) (*bundlepb.SignedKeyset, error) {
	if ks.FormatVersion == 0 {
		ks.FormatVersion = FormatVersion
	}
	kb, err := marshal.Marshal(ks)
	if err != nil {
		return nil, err
	}
	sig, err := root.Sign(KeysetSigningInput(kb))
	if err != nil {
		return nil, fmt.Errorf("sign keyset: %w", err)
	}
	return &bundlepb.SignedKeyset{Keyset: kb, Signature: sig, RootKeyId: root.KeyID()}, nil
}

// Marshal serializes a signed bundle for transport.
func Marshal(sb *bundlepb.SignedBundle) ([]byte, error) { return marshal.Marshal(sb) }

// newUUIDv7 returns a RFC 9562 version 7 UUID string.
func newUUIDv7(t time.Time) string {
	var b [16]byte
	_, _ = rand.Read(b[:])
	ms := uint64(t.UnixMilli())
	b[0], b[1], b[2] = byte(ms>>40), byte(ms>>32), byte(ms>>24)
	b[3], b[4], b[5] = byte(ms>>16), byte(ms>>8), byte(ms)
	b[6] = (b[6] & 0x0f) | 0x70
	b[8] = (b[8] & 0x3f) | 0x80
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16])
}
