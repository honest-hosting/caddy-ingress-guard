// Package ingressguard is the ingress-guard Caddy module: a Caddy app that verifies and activates
// signed policy bundles pushed by a local agent, and HTTP handlers that enforce the active policy.
//
// Spike prototype (Phase 02 S2, S3): site and multi modes accept bundles on a loopback push
// endpoint; static mode builds from Caddy config. Multi mode selects a base profile per site
// (multi.go). The access-stage controls (Phase 09) are not implemented yet.
package ingressguard

import (
	"crypto/ed25519"
	"encoding/base64"
	"fmt"
	"net"
	"strings"

	"github.com/caddyserver/caddy/v2"
	"github.com/prometheus/client_golang/prometheus"
	"go.uber.org/zap"

	"github.com/honest-hosting/caddy-ingress-guard/bundle"
)

// ModuleVersion is compared against a section's min_module_version. Release builds set it with
// -ldflags "-X github.com/honest-hosting/caddy-ingress-guard.ModuleVersion=v0.1.0".
var ModuleVersion = "v0.0.0-spike"

// Modes.
const (
	ModeSite   = "site"
	ModeMulti  = "multi"
	ModeStatic = "static"
)

// DefaultSiteIdentity is where multi mode reads a route's site identity by default.
const DefaultSiteIdentity = "{http.vars.hh.site}"

// The runtime (active bundles, built WAFs, push listener, metrics) lives in a usage pool so it
// survives Caddy config reloads: the new app takes the existing runtime before the old one lets
// go of it.
var runtimes = caddy.NewUsagePool()

const runtimePoolKey = "ingress_guard"

func init() {
	caddy.RegisterModule(App{})
}

// App is the ingress_guard Caddy app.
type App struct {
	// Mode is site (FrankenWP), multi (ingress tier) or static (rules from config).
	Mode string `json:"mode,omitempty"`
	// Targets this module accepts bundles for. Site mode: layer:global, layer:dc:<dc>,
	// site:<uuid>. Multi mode: ingress:<pool>.
	Targets []string `json:"targets,omitempty"`
	// RootKeys maps root key ID to base64 Ed25519 public key. Two roots may overlap for rotation.
	RootKeys map[string]string `json:"root_keys,omitempty"`
	// PushListen is the loopback address of the bundle push endpoint, e.g. 127.0.0.1:2020.
	PushListen string `json:"push_listen,omitempty"`
	// StaleBootstrap accepts an expired bundle when no bundle is active for its target (the
	// ingress-tier agent's last-known-good). Never enable it where tenant code runs.
	StaleBootstrap bool `json:"stale_bootstrap,omitempty"`
	// StaticDirectives (static mode) is SecLang loaded at provision time.
	StaticDirectives string `json:"static_directives,omitempty"`
	// StaticFile (static mode) is a SecLang file loaded at provision time.
	StaticFile string `json:"static_file,omitempty"`
	// SiteIdentity (multi mode) is the placeholder holding the route's site identity, never
	// the Host header (FR-04). Default: {http.vars.hh.site}, set by caddy-consul's
	// consul_route_info.
	SiteIdentity string `json:"site_identity,omitempty"`

	rt     *runtime
	logger *zap.Logger
}

// CaddyModule returns the Caddy module information.
func (App) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "ingress_guard",
		New: func() caddy.Module { return new(App) },
	}
}

// Provision sets up the app and attaches it to the shared runtime.
func (a *App) Provision(ctx caddy.Context) error {
	a.logger = ctx.Logger()
	if a.Mode == "" {
		a.Mode = ModeSite
	}
	if a.Mode == ModeMulti && a.SiteIdentity == "" {
		a.SiteIdentity = DefaultSiteIdentity
	}
	cfg, err := a.runtimeConfig()
	if err != nil {
		return err
	}

	val, _, err := runtimes.LoadOrNew(runtimePoolKey, func() (caddy.Destructor, error) {
		return newRuntime(), nil
	})
	if err != nil {
		return err
	}
	a.rt = val.(*runtime)
	a.rt.setLogger(a.logger)
	a.rt.configure(cfg)

	for _, c := range a.rt.metrics.collectors() {
		if err := ctx.GetMetricsRegistry().Register(c); err != nil {
			if _, dup := err.(prometheus.AlreadyRegisteredError); !dup {
				return fmt.Errorf("registering metrics: %w", err)
			}
		}
	}

	if a.Mode == ModeStatic {
		return a.rt.loadStatic(a.StaticDirectives, a.StaticFile)
	}
	return nil
}

func (a *App) runtimeConfig() (*runtimeConfig, error) {
	cfg := &runtimeConfig{
		mode:           a.Mode,
		targets:        map[string]bool{},
		staleBootstrap: a.StaleBootstrap,
	}
	switch a.Mode {
	case ModeStatic:
		if a.StaticDirectives == "" && a.StaticFile == "" {
			return nil, fmt.Errorf("ingress_guard: static mode needs static_directives or static_file")
		}
		if a.PushListen != "" {
			return nil, fmt.Errorf("ingress_guard: static mode has no push endpoint")
		}
		return cfg, nil
	case ModeSite, ModeMulti:
		if a.SiteIdentity != "" && a.Mode != ModeMulti {
			return nil, fmt.Errorf("ingress_guard: site_identity is a multi-mode option")
		}
	default:
		return nil, fmt.Errorf("ingress_guard: unknown mode %q", a.Mode)
	}

	for _, t := range a.Targets {
		if !bundle.ValidTarget(t) {
			return nil, fmt.Errorf("ingress_guard: invalid target %q", t)
		}
		isIngress := strings.HasPrefix(t, bundle.TargetIngressPrefix)
		if (a.Mode == ModeMulti) != isIngress {
			return nil, fmt.Errorf("ingress_guard: target %q not allowed in %s mode", t, a.Mode)
		}
		cfg.targets[t] = true
	}
	if len(cfg.targets) == 0 {
		return nil, fmt.Errorf("ingress_guard: %s mode needs at least one target", a.Mode)
	}

	roots := map[string]ed25519.PublicKey{}
	for id, b64 := range a.RootKeys {
		k, err := base64.StdEncoding.DecodeString(b64)
		if err != nil || len(k) != ed25519.PublicKeySize {
			return nil, fmt.Errorf("ingress_guard: root key %q is not a base64 Ed25519 public key", id)
		}
		roots[id] = ed25519.PublicKey(k)
	}
	if len(roots) == 0 {
		return nil, fmt.Errorf("ingress_guard: at least one root_key is required")
	}
	cfg.verifier = &bundle.Verifier{RootKeys: roots}

	if a.PushListen == "" {
		return nil, fmt.Errorf("ingress_guard: push_listen is required in %s mode", a.Mode)
	}
	if err := requireLoopback(a.PushListen); err != nil {
		return nil, err
	}
	cfg.pushListen = a.PushListen
	return cfg, nil
}

// requireLoopback enforces that the push endpoint never listens beyond loopback.
func requireLoopback(addr string) error {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return fmt.Errorf("ingress_guard: push_listen %q: %w", addr, err)
	}
	if host == "localhost" {
		return nil
	}
	ip := net.ParseIP(host)
	if ip == nil || !ip.IsLoopback() {
		return fmt.Errorf("ingress_guard: push_listen %q must be a loopback address", addr)
	}
	return nil
}

// Start starts the push endpoint (once; it survives reloads with the runtime).
func (a *App) Start() error {
	if a.Mode == ModeStatic {
		return nil
	}
	return a.rt.ensureServer()
}

// Stop does nothing: the runtime and its listener outlive a config reload and are destroyed when
// the last app releases them (Cleanup).
func (a *App) Stop() error { return nil }

// Cleanup releases this app's hold on the shared runtime.
func (a *App) Cleanup() error {
	_, err := runtimes.Delete(runtimePoolKey)
	return err
}

// Interface guards.
var (
	_ caddy.App          = (*App)(nil)
	_ caddy.Provisioner  = (*App)(nil)
	_ caddy.CleanerUpper = (*App)(nil)
)
