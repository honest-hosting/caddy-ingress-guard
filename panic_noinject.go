//go:build !ingressguard_panicinject

package ingressguard

import "net/http"

func maybePanicRequest(*http.Request) {}

func maybePanicBuild(string) {}
