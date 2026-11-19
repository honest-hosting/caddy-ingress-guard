package ingressguard

import (
	"fmt"
	"net/http"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"github.com/corazawaf/coraza/v3"
	"go.uber.org/zap"

	"github.com/honest-hosting/caddy-ingress-guard/bundle"
)

// Stages (A1 §5.4): access controls run before sidekick on every request; WAF inspection runs
// directly before php_server, so only cache misses (the requests that run PHP) are inspected.
const (
	StageAccess  = "access"
	StageInspect = "inspect"
)

func init() {
	caddy.RegisterModule(Handler{})
}

// Handler enforces the active bundle, or its own static rules, for one stage of the request
// chain.
type Handler struct {
	Stage string `json:"stage,omitempty"`
	// StaticDirectives and StaticFile (inspect stage) give this handler its own SecLang rules
	// from Caddy config, loaded once per config load (DR-03). Such a handler ignores the app's
	// bundles, profiles and force_mode, whatever the app's mode, so manually defined routes run
	// static rules beside multi-mode site routes in one Caddy. The directives come first, then
	// the file; neither gets engine defaults.
	StaticDirectives string `json:"static_directives,omitempty"`
	StaticFile       string `json:"static_file,omitempty"`

	app    *App
	logger *zap.Logger
	events *zap.Logger // WAF event lines (event.go)
	static coraza.WAF  // this handler's own rules, or nil
}

// CaddyModule returns the Caddy module information.
func (Handler) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "http.handlers.ingress_guard",
		New: func() caddy.Module { return new(Handler) },
	}
}

// Provision attaches the handler to the ingress_guard app and builds its static rules, if any.
func (h *Handler) Provision(ctx caddy.Context) error {
	h.logger = ctx.Logger()
	h.events = h.logger.Named("event")
	switch h.Stage {
	case "":
		h.Stage = StageInspect
	case StageAccess, StageInspect:
	default:
		return fmt.Errorf("ingress_guard: unknown stage %q", h.Stage)
	}
	hasStatic := h.StaticDirectives != "" || h.StaticFile != ""
	if hasStatic && h.Stage != StageInspect {
		return fmt.Errorf("ingress_guard: static rules belong on the %s stage", StageInspect)
	}
	appIface, err := ctx.App("ingress_guard")
	if err != nil {
		return fmt.Errorf("ingress_guard: loading app: %w", err)
	}
	h.app = appIface.(*App)
	if hasStatic {
		waf, err := buildStatic(h.StaticDirectives, h.StaticFile)
		if err != nil {
			return err
		}
		h.static = waf
	}
	return nil
}

// Cleanup closes this handler's static WAF when its config is unloaded, releasing its share of
// Coraza's pattern cache (see closeWAF). In-flight transactions keep their own references.
func (h *Handler) Cleanup() error {
	if h.static != nil {
		closeWAF(h.static)
		h.static = nil
	}
	return nil
}

// ServeHTTP runs the stage. Panics inside the module fail open for that request (DR-08); a panic
// raised downstream (after next was called) is not swallowed.
func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request, next caddyhttp.Handler) (err error) {
	if h.Stage == StageAccess {
		// Phase 09: IP / geo / rate / challenge controls. Nothing to enforce yet.
		return next.ServeHTTP(w, r)
	}

	rt := h.app.rt
	in, pass := h.selectWAF(r)
	if pass {
		return next.ServeHTTP(w, r)
	}

	nextCalled := false
	defer func() {
		rec := recover()
		if rec == nil {
			return
		}
		if nextCalled {
			panic(rec) // not ours: let Caddy's own recovery handle it
		}
		rt.metrics.panics.WithLabelValues("request").Inc()
		h.logger.Error("ingress_guard: panic in request inspection, serving open",
			zap.Any("panic", rec), zap.String("uri", r.RequestURI))
		nextCalled = true
		err = next.ServeHTTP(w, r)
	}()

	maybePanicRequest(r)
	rt.metrics.requests.WithLabelValues("inspected").Inc()
	return h.inspect(w, r, next, in, &nextCalled)
}

// selectWAF picks the WAF for this request: the handler's static rules, the site's profile
// (multi mode) or the active bundle's WAF. pass is true when the request is not inspected (no
// WAF: unprotected, off by policy, or no site identity in multi mode); the reason is counted.
//
// The WAF comes from this request's snapshot, so a swap mid-request never changes the rules a
// request is evaluated against; replaced instances are closed straight after the swap, which is
// safe because in-flight transactions keep their own references.
func (h *Handler) selectWAF(r *http.Request) (in *inspection, pass bool) {
	m := h.app.rt.metrics
	if h.static != nil {
		return &inspection{waf: h.static, mode: ModeStatic}, false
	}
	snap := h.app.rt.snapshot()
	in = &inspection{mode: h.app.Mode, snap: snap, forced: h.app.forceDetect()}
	e := snap.enginesOrZero()
	if h.app.Mode == ModeMulti {
		// Only the module sets the site header, and only inside the transaction (inspect.go).
		r.Header.Del(bundle.SiteHeader)
		site := h.siteIdentity(r)
		if site == "" {
			// D11, FR-18: a route without an identity belongs on a static-rules handler, never on
			// the bundle's default profile.
			m.noIdentity.Inc()
			m.requests.WithLabelValues("no_identity").Inc()
			return nil, true
		}
		in.site = site
		if e.multi != nil {
			p := e.multi.forSite(site)
			m.profileRequests.WithLabelValues(p.name).Inc()
			in.waf, in.profile = p.waf, p.name
		}
	} else {
		in.waf, in.site = e.waf, h.app.siteID
	}
	if in.waf == nil {
		if snap.unprotected() {
			m.requests.WithLabelValues("unprotected").Inc()
		} else {
			m.requests.WithLabelValues("off").Inc()
		}
		return nil, true
	}
	return in, false
}

// siteIdentity resolves the app's site_identity placeholder (multi mode), e.g. the
// {http.vars.hh.site} that caddy-consul's consul_route_info sets from the route's Consul tags.
// Empty when the route carries no identity.
func (h *Handler) siteIdentity(r *http.Request) string {
	return resolve(r, h.app.SiteIdentity)
}

// resolve expands a placeholder string with the request's replacer; "" without one.
func resolve(r *http.Request, placeholder string) string {
	if placeholder == "" {
		return ""
	}
	repl, ok := r.Context().Value(caddy.ReplacerCtxKey).(*caddy.Replacer)
	if !ok {
		return ""
	}
	return repl.ReplaceAll(placeholder, "")
}

// Interface guards.
var (
	_ caddy.Provisioner           = (*Handler)(nil)
	_ caddy.CleanerUpper          = (*Handler)(nil)
	_ caddyhttp.MiddlewareHandler = (*Handler)(nil)
)
