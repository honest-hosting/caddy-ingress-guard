//go:build ingressguard_panicinject

package ingressguard

import (
	"net/http"
	"strings"
)

// Spike S2 panic injection, compiled in only with -tags ingressguard_panicinject.
//
//   - request path: a request carrying "X-Ingress-Guard-Panic: request" panics inside inspection;
//   - background build: a bundle whose SecLang contains "ingress-guard:panic-build" panics while
//     its WAF is built.

func maybePanicRequest(r *http.Request) {
	if r.Header.Get("X-Ingress-Guard-Panic") == "request" {
		panic("ingress_guard: injected request panic")
	}
}

func maybePanicBuild(directives string) {
	if strings.Contains(directives, "ingress-guard:panic-build") {
		panic("ingress_guard: injected build panic")
	}
}
