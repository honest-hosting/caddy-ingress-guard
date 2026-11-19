package main

import (
	"testing"

	"github.com/corazawaf/coraza/v3"

	"github.com/honest-hosting/caddy-ingress-guard/bundle"
)

// hostRules' gates may only skip. Every site must get exactly its own exclusions, and the rule
// right after host_rules must run for every request: a wrong skip:N would silently skip it (in a
// real bundle, CRS setup).
func TestHostRulesLayout(t *testing.T) {
	const sites = 30 // ceil(√30) = 6 per bucket: 5 buckets
	bySite := map[string][]exclusion{}
	for i := range sites {
		e := exclusion{ctl: "ctl:ruleRemoveById=9001"} // even sites: everywhere
		if i%2 == 1 {
			e.path = "/allowed/" // odd sites: under /allowed/ only
		}
		bySite[siteID(i)] = []exclusion{e}
		if i%3 == 0 { // a second, shared exclusion, so buckets hold more than one rule
			bySite[siteID(i)] = append(bySite[siteID(i)], exclusion{ctl: "ctl:ruleRemoveById=9004"})
		}
	}
	id := hostRuleID
	rules, nRules, buckets := hostRules(bySite, &id)
	if buckets != 5 || nRules == 0 {
		t.Fatalf("buckets %d, rules %d", buckets, nRules)
	}
	waf, err := coraza.NewWAF(coraza.NewWAFConfig().WithDirectives("SecRuleEngine On\n" + rules + `
SecAction "id:9000,phase:1,pass,nolog,setvar:tx.after_host_rules=1"
SecRule &TX:after_host_rules "@eq 0" "id:9003,phase:1,deny,status:418"
SecRule REQUEST_URI "@beginsWith /" "id:9001,phase:1,deny,status:403"
`))
	if err != nil {
		t.Fatal(err)
	}
	status := func(site, path string) int {
		tx := waf.NewTransaction()
		defer tx.Close()
		tx.ProcessConnection("192.0.2.1", 40000, "", 0)
		tx.ProcessURI(path, "GET", "HTTP/1.1")
		if site != "" {
			tx.AddRequestHeader(bundle.SiteHeader, site)
		}
		if it := tx.ProcessRequestHeaders(); it != nil {
			return it.Status
		}
		return 200
	}
	for i := range sites {
		wantX := 403
		if i%2 == 0 {
			wantX = 200
		}
		if got := status(siteID(i), "/x"); got != wantX {
			t.Errorf("site %d /x: got %d, want %d", i, got, wantX)
		}
		if got := status(siteID(i), "/allowed/x"); got != 200 {
			t.Errorf("site %d /allowed/x: got %d, want 200", i, got)
		}
	}
	for _, site := range []string{siteID(sites + 1), ""} { // no exclusions; no identity
		for _, path := range []string{"/x", "/allowed/x"} {
			if got := status(site, path); got != 403 {
				t.Errorf("site %q %s: got %d, want 403", site, path, got)
			}
		}
	}
}
