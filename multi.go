package ingressguard

import (
	"errors"
	"fmt"

	"github.com/corazawaf/coraza/v3"

	"github.com/honest-hosting/caddy-ingress-guard/bundle/bundlepb"
)

// Multi mode (the ingress tier, S3): one WAF instance per base profile, shared by every site on
// that profile. Per-site exclusions are host_rules inside the profile, keyed on the site identity
// the handler adds to each transaction (bundle.SiteHeader, inspect.go). A few instances keep
// memory and rebuild time low while every site keeps its own exceptions.

// profileWAF is one built profile. waf is nil when the profile's mode is off.
type profileWAF struct {
	name string
	waf  coraza.WAF
}

// multiSet is a built profiles section. Immutable once stored in a snapshot.
type multiSet struct {
	profiles []*profileWAF
	bySite   map[string]*profileWAF
	def      *profileWAF
}

// forSite returns the site's profile, or the default for a site the bundle doesn't list. The
// handler never asks for an empty identity: those requests pass through (no_identity).
func (m *multiSet) forSite(site string) *profileWAF {
	if p, ok := m.bySite[site]; ok {
		return p
	}
	return m.def
}

func (m *multiSet) close() {
	if m == nil {
		return
	}
	for _, p := range m.profiles {
		if p.waf != nil {
			closeWAF(p.waf)
		}
	}
}

// buildProfiles builds one WAF per profile. On an error or a panic it closes what it built, so a
// failed build leaks nothing; the caller's recover turns a panic into a rejected bundle.
func (c *composed) buildProfiles() (_ *multiSet, err error) {
	ps := c.profiles
	if ps == nil || len(ps.GetProfiles()) == 0 {
		return nil, errors.New("multi mode: bundle has no profiles")
	}
	set := &multiSet{bySite: make(map[string]*profileWAF, len(ps.GetSites()))}
	done := false
	defer func() {
		if !done {
			set.close()
		}
	}()

	byName := make(map[string]*profileWAF, len(ps.GetProfiles()))
	for _, p := range ps.GetProfiles() {
		if p.GetName() == "" || byName[p.GetName()] != nil {
			return nil, fmt.Errorf("profile name %q is empty or repeated", p.GetName())
		}
		pw := &profileWAF{name: p.GetName()}
		mode := p.GetMode()
		if c.mode == bundlepb.Mode_MODE_DETECT {
			mode = bundlepb.Mode_MODE_DETECT // pool-wide detection-only
		}
		if mode != bundlepb.Mode_MODE_OFF {
			waf, err := c.newWAF(c.directives(p.GetHostRules(), p.GetCrsSetup(), mode))
			if err != nil {
				return nil, fmt.Errorf("profile %s: %w", p.GetName(), err)
			}
			pw.waf = waf
		}
		set.profiles = append(set.profiles, pw)
		byName[pw.name] = pw
	}
	if set.def = byName[ps.GetDefaultProfile()]; set.def == nil {
		return nil, fmt.Errorf("default profile %q is not defined", ps.GetDefaultProfile())
	}
	for site, name := range ps.GetSites() {
		pw := byName[name]
		if pw == nil {
			return nil, fmt.Errorf("site %s: profile %q is not defined", site, name)
		}
		set.bySite[site] = pw
	}
	done = true
	return set, nil
}
