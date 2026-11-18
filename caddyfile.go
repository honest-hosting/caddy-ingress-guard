package ingressguard

import (
	"github.com/caddyserver/caddy/v2/caddyconfig"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/caddyconfig/httpcaddyfile"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
)

func init() {
	httpcaddyfile.RegisterGlobalOption("ingress_guard", parseGlobalOption)
	// Two directive names, so each stage gets its own place in the handler order:
	//   order ingress_guard_access before sidekick
	//   order ingress_guard_inspect before php_server
	httpcaddyfile.RegisterHandlerDirective("ingress_guard_access", parseStage(StageAccess))
	httpcaddyfile.RegisterHandlerDirective("ingress_guard_inspect", parseStage(StageInspect))
}

// parseGlobalOption parses:
//
//	ingress_guard {
//		mode site|multi|static
//		target <target...>          # also: layers <target...>
//		root_key <id> <base64>      # repeatable
//		push_listen 127.0.0.1:2020
//		stale_bootstrap             # ingress tier only
//		static_directives <seclang> # static mode
//		static_file <path>          # static mode
//		site_identity <placeholder> # multi mode; default {http.vars.hh.site}
//	}
func parseGlobalOption(d *caddyfile.Dispenser, _ any) (any, error) {
	app := &App{RootKeys: map[string]string{}}
	d.Next() // option name
	for d.NextBlock(0) {
		switch d.Val() {
		case "mode":
			if !d.NextArg() {
				return nil, d.ArgErr()
			}
			app.Mode = d.Val()
		case "target", "targets", "layers":
			args := d.RemainingArgs()
			if len(args) == 0 {
				return nil, d.ArgErr()
			}
			app.Targets = append(app.Targets, args...)
		case "root_key":
			args := d.RemainingArgs()
			if len(args) != 2 {
				return nil, d.ArgErr()
			}
			app.RootKeys[args[0]] = args[1]
		case "push_listen":
			if !d.NextArg() {
				return nil, d.ArgErr()
			}
			app.PushListen = d.Val()
		case "stale_bootstrap":
			app.StaleBootstrap = true
			if d.NextArg() {
				app.StaleBootstrap = d.Val() == "on" || d.Val() == "true"
			}
		case "static_directives":
			if !d.NextArg() {
				return nil, d.ArgErr()
			}
			app.StaticDirectives = d.Val()
		case "static_file":
			if !d.NextArg() {
				return nil, d.ArgErr()
			}
			app.StaticFile = d.Val()
		case "site_identity":
			if !d.NextArg() {
				return nil, d.ArgErr()
			}
			app.SiteIdentity = d.Val()
		default:
			return nil, d.Errf("unknown ingress_guard option %q", d.Val())
		}
	}
	return httpcaddyfile.App{Name: "ingress_guard", Value: caddyconfig.JSON(app, nil)}, nil
}

func parseStage(stage string) func(h httpcaddyfile.Helper) (caddyhttp.MiddlewareHandler, error) {
	return func(h httpcaddyfile.Helper) (caddyhttp.MiddlewareHandler, error) {
		h.Next() // directive name
		if h.NextArg() {
			return nil, h.ArgErr()
		}
		return &Handler{Stage: stage}, nil
	}
}
