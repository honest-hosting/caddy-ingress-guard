package ingressguard

import (
	"fmt"
	"net/http"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	corazahttp "github.com/corazawaf/coraza/v3/http"
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

// Handler enforces the active bundle for one stage of the request chain.
type Handler struct {
	Stage string `json:"stage,omitempty"`

	app    *App
	logger *zap.Logger
}

// CaddyModule returns the Caddy module information.
func (Handler) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "http.handlers.ingress_guard",
		New: func() caddy.Module { return new(Handler) },
	}
}

// Provision attaches the handler to the ingress_guard app.
func (h *Handler) Provision(ctx caddy.Context) error {
	h.logger = ctx.Logger()
	switch h.Stage {
	case "":
		h.Stage = StageInspect
	case StageAccess, StageInspect:
	default:
		return fmt.Errorf("ingress_guard: unknown stage %q", h.Stage)
	}
	appIface, err := ctx.App("ingress_guard")
	if err != nil {
		return fmt.Errorf("ingress_guard: loading app: %w", err)
	}
	h.app = appIface.(*App)
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
	snap := rt.snapshot()
	waf := snap.enginesOrZero().waf
	if snap != nil && snap.multi != nil {
		// Multi mode: the route's site picks the profile. Only the module sets the site header,
		// and only inside the transaction (siteWAF).
		r.Header.Del(bundle.SiteHeader)
		site := h.siteIdentity(r)
		p := snap.multi.forSite(site)
		rt.metrics.profileRequests.WithLabelValues(p.name).Inc()
		if waf = p.waf; waf != nil && site != "" {
			r = r.WithContext(withSite(r.Context(), site))
		}
	}
	if waf == nil {
		if snap.unprotected() {
			rt.metrics.requests.WithLabelValues("unprotected").Inc()
		} else {
			rt.metrics.requests.WithLabelValues("off").Inc()
		}
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
	// The transaction is created from this request's snapshot, so a swap mid-request never
	// changes the rules a request is evaluated against; old instances are collected once their
	// last transaction finishes.
	corazahttp.WrapHandler(waf, http.HandlerFunc(func(w2 http.ResponseWriter, r2 *http.Request) {
		nextCalled = true
		err = next.ServeHTTP(w2, r2)
	})).ServeHTTP(w, r)
	return err
}

// siteIdentity resolves the app's site_identity placeholder (multi mode), e.g. the
// {http.vars.hh.site} that caddy-consul's consul_route_info sets from the route's Consul tags.
// Empty when the route carries no identity.
func (h *Handler) siteIdentity(r *http.Request) string {
	repl, ok := r.Context().Value(caddy.ReplacerCtxKey).(*caddy.Replacer)
	if !ok || h.app.SiteIdentity == "" {
		return ""
	}
	return repl.ReplaceAll(h.app.SiteIdentity, "")
}

// Interface guards.
var (
	_ caddy.Provisioner           = (*Handler)(nil)
	_ caddyhttp.MiddlewareHandler = (*Handler)(nil)
)
