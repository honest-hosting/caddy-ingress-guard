// Package ingressguard is the ingress-guard Caddy module: a Caddy app that verifies and activates
// signed policy bundles pushed by a local agent, and HTTP handlers that enforce the active policy.
//
// Site and multi modes accept bundles on a loopback push endpoint; static mode builds from Caddy
// config. Multi mode selects a base profile per site (multi.go). A handler can also carry its own
// static rules (static_file / static_directives), so routes on static rules and routes on bundles
// share one Caddy. Blocks are returned as Caddy errors (handle_errors renders them), and every
// matched or interrupted transaction is one structured log line (event.go). The access-stage
// controls (Phase 09) are not implemented yet.
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

// DefaultTenantIdentity is where multi mode reads a route's tenant by default. It only labels
// WAF event log lines; it never selects policy.
const DefaultTenantIdentity = "{http.vars.hh.tenant}"

// ForceDetect is the force_mode value that makes all bundle-driven enforcement detection-only.
const ForceDetect = "detect"

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
	// consul_route_info. A request whose identity is empty is passed through uninspected (and
	// counted): routes without an identity belong on a handler with static rules.
	SiteIdentity string `json:"site_identity,omitempty"`
	// TenantIdentity is a placeholder for the request's tenant, used only to label WAF event
	// log lines. Multi mode default: {http.vars.hh.tenant}.
	TenantIdentity string `json:"tenant_identity,omitempty"`
	// ForceMode "detect" (multi mode only) makes all bundle-driven enforcement detection-only,
	// whatever the bundle's switches and profiles say: a would-be block is logged as
	// would_block and the request is served. It is the ingress tier's local break-glass
	// override. Refused in site mode, and meaningless in static mode. Handlers with their own
	// static rules are not bundle-driven and keep enforcing.
	ForceMode string `json:"force_mode,omitempty"`
	// TxIDHeader names a request header whose value becomes the WAF transaction ID (and the ID
	// of a block's Caddy error), e.g. X-Request-ID, so WAF events join other logs by request
	// ID. Set it only where an earlier route replaces any client-sent copy of that header. An
	// absent or malformed value falls back to Caddy's request UUID ({http.request.uuid}).
	TxIDHeader string `json:"tx_id_header,omitempty"`

	rt     *runtime
	logger *zap.Logger
	siteID string // site mode: the site:<uuid> target's UUID, for event lines
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
	if a.Mode == ModeMulti {
		if a.SiteIdentity == "" {
			a.SiteIdentity = DefaultSiteIdentity
		}
		if a.TenantIdentity == "" {
			a.TenantIdentity = DefaultTenantIdentity
		}
	}
	cfg, err := a.runtimeConfig()
	if err != nil {
		return err
	}
	for _, t := range a.Targets {
		if strings.HasPrefix(t, bundle.TargetSitePrefix) {
			a.siteID = strings.TrimPrefix(t, bundle.TargetSitePrefix)
		}
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
	switch a.ForceMode {
	case "":
	case ForceDetect:
		// DR-11 break-glass (c): an ingress-tier option only. In site mode tenant code shares
		// the host, and static mode has no bundle to override.
		if a.Mode != ModeMulti {
			return nil, fmt.Errorf("ingress_guard: force_mode is a multi-mode (ingress tier) option; refused in %s mode", a.Mode)
		}
	default:
		return nil, fmt.Errorf("ingress_guard: unknown force_mode %q (only %q)", a.ForceMode, ForceDetect)
	}
	if a.TxIDHeader != "" && !validHeaderName(a.TxIDHeader) {
		return nil, fmt.Errorf("ingress_guard: tx_id_header %q is not a valid header name", a.TxIDHeader)
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

// validHeaderName reports whether s is an HTTP header field name (an RFC 9110 token).
func validHeaderName(s string) bool {
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9':
		case strings.IndexByte("!#$%&'*+-.^_`|~", c) >= 0:
		default:
			return false
		}
	}
	return s != ""
}

// Start starts the push endpoint (once; it survives reloads with the runtime). force_mode is read
// per request from this config's app, so a reload switches it with no rebuild; the gauge follows
// the config that is starting.
func (a *App) Start() error {
	forced := a.ForceMode == ForceDetect
	a.rt.setForceDetect(forced)
	if forced {
		a.logger.Warn("ingress_guard: force_mode detect: bundle-driven enforcement is detection-only (break-glass)")
	}
	if a.Mode == ModeStatic {
		return nil
	}
	return a.rt.ensureServer()
}

// forceDetect reports whether bundle-driven enforcement is forced to detection-only.
func (a *App) forceDetect() bool { return a.ForceMode == ForceDetect }

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
