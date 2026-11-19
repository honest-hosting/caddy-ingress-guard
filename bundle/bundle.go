// Package bundle builds, signs and verifies ingress-guard bundles: the module's public contract
// (proto/ingressguard/v1/bundle.proto).
//
// Producers (the HH security service, test tools) use Build and SignKeyset. The module uses Peek,
// Verifier and OpenPayload, in that order, so the cheap checks come first and nothing is acted on
// before the signature verifies.
package bundle

import (
	"crypto/ed25519"
	"errors"
	"fmt"
	"strings"

	"golang.org/x/mod/semver"

	"github.com/honest-hosting/caddy-ingress-guard/bundle/bundlepb"
)

// FormatVersion is the only manifest and keyset format this package produces and accepts.
const FormatVersion = 1

// Size caps. A push body larger than MaxSignedBundleBytes is rejected before parsing.
const (
	MaxSignedBundleBytes = 4 << 20
	MaxManifestBytes     = 64 << 10
	MaxKeysetBytes       = 64 << 10
	MaxPayloadBytes      = 32 << 20
)

// Domain prefixes: a signature made for one purpose is never valid for another.
const (
	manifestDomain = "ingress-guard bundle v1\n"
	keysetDomain   = "ingress-guard keyset v1\n"
)

// Section names (v1).
const (
	SectionCoraza         = "coraza"
	SectionCRS            = "crs"
	SectionTrustedProxies = "trusted_proxies"
	SectionSwitches       = "switches"
	SectionProfiles       = "profiles"
)

// SiteHeader carries the route's site identity inside a multi-mode transaction, where a
// profile's host_rules match it. It is never forwarded, and a client's copy is removed first.
const SiteHeader = "X-Ingress-Guard-Site"

// Target prefixes.
const (
	TargetGlobal        = "layer:global"
	TargetDCPrefix      = "layer:dc:"
	TargetSitePrefix    = "site:"
	TargetIngressPrefix = "ingress:"
)

// Rejection reasons, reported in Ack.reason and in the rejected-bundle metric.
const (
	ReasonTooLarge           = "too_large"
	ReasonMalformed          = "malformed"
	ReasonUnsupportedFormat  = "unsupported_format"
	ReasonWrongTarget        = "wrong_target"
	ReasonOldSequence        = "old_sequence"
	ReasonBadKeyset          = "bad_keyset"
	ReasonUnknownKey         = "unknown_key"
	ReasonBadSignature       = "bad_signature"
	ReasonNotYetValid        = "not_yet_valid"
	ReasonExpired            = "expired"
	ReasonBadPayload         = "bad_payload"
	ReasonUnsupportedSection = "unsupported_section"
	ReasonBuildFailed        = "build_failed"
	ReasonRateLimited        = "rate_limited"
)

// Error carries a rejection reason code plus detail.
type Error struct {
	Reason string
	Detail string
}

func (e *Error) Error() string {
	if e.Detail == "" {
		return e.Reason
	}
	return e.Reason + ": " + e.Detail
}

func reject(reason, format string, args ...any) error {
	return &Error{Reason: reason, Detail: fmt.Sprintf(format, args...)}
}

// ReasonOf returns the rejection reason of err, or ReasonMalformed for foreign errors.
func ReasonOf(err error) string {
	var e *Error
	if errors.As(err, &e) {
		return e.Reason
	}
	return ReasonMalformed
}

// ValidTarget reports whether t is a well-formed target ID.
func ValidTarget(t string) bool {
	switch {
	case t == TargetGlobal:
		return true
	case strings.HasPrefix(t, TargetDCPrefix):
		return len(t) > len(TargetDCPrefix)
	case strings.HasPrefix(t, TargetSitePrefix):
		return len(t) > len(TargetSitePrefix)
	case strings.HasPrefix(t, TargetIngressPrefix):
		return len(t) > len(TargetIngressPrefix)
	}
	return false
}

// LayerRank orders a site's layers for composition: global, then DC, then site.
func LayerRank(t string) int {
	switch {
	case t == TargetGlobal:
		return 0
	case strings.HasPrefix(t, TargetDCPrefix):
		return 1
	case strings.HasPrefix(t, TargetSitePrefix):
		return 2
	default:
		return 3
	}
}

// Signer signs with Ed25519. A Vault Transit signer implements it in the security service; the
// test tool uses Ed25519Signer.
type Signer interface {
	KeyID() string
	Sign(msg []byte) ([]byte, error)
}

// Ed25519Signer signs with a local private key (tests, localdev, the open-source dev flow).
type Ed25519Signer struct {
	ID  string
	Key ed25519.PrivateKey
}

// KeyID implements Signer.
func (s Ed25519Signer) KeyID() string { return s.ID }

// Sign implements Signer.
func (s Ed25519Signer) Sign(msg []byte) ([]byte, error) { return ed25519.Sign(s.Key, msg), nil }

// ManifestSigningInput is what a signer signs for a bundle: the domain prefix plus the exact
// manifest bytes. Transit signers receive this as their (base64) input.
func ManifestSigningInput(manifest []byte) []byte {
	return append([]byte(manifestDomain), manifest...)
}

// KeysetSigningInput is what the root key signs for a keyset.
func KeysetSigningInput(keyset []byte) []byte {
	return append([]byte(keysetDomain), keyset...)
}

// SectionSupported reports whether a section header can be honored by a module that knows the
// given sections at moduleVersion. Non-semver module versions (development builds) accept any
// minimum.
func SectionSupported(h *bundlepb.SectionHeader, known map[string]bool, moduleVersion string) bool {
	if !known[h.GetName()] {
		return false
	}
	min := h.GetMinModuleVersion()
	if min == "" || !semver.IsValid(moduleVersion) {
		return true
	}
	if !semver.IsValid(min) {
		return false
	}
	return semver.Compare(moduleVersion, min) >= 0
}
