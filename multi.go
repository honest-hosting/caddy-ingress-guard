package ingressguard

import (
	"context"
	"errors"
	"fmt"

	"github.com/corazawaf/coraza/v3"
	"github.com/corazawaf/coraza/v3/experimental"
	"github.com/corazawaf/coraza/v3/types"

	"github.com/honest-hosting/caddy-ingress-guard/bundle"
	"github.com/honest-hosting/caddy-ingress-guard/bundle/bundlepb"
)

// Multi mode (the ingress tier, S3): one WAF instance per base profile, shared by every site on
// that profile. Per-site exclusions are host_rules inside the profile, keyed on the site identity
// the module adds to each transaction (bundle.SiteHeader). A few instances keep memory and
// rebuild time low while every site keeps its own exceptions.

// profileWAF is one built profile. waf is nil when the profile's mode is off.
type profileWAF struct {
	name string
	waf  coraza.WAF // raw wrapped in siteWAF
	raw  coraza.WAF // what closeWAF releases
}

// multiSet is a built profiles section. Immutable once stored in a snapshot.
type multiSet struct {
	profiles []*profileWAF
	bySite   map[string]*profileWAF
	def      *profileWAF
}

// forSite returns the site's profile: the default for an unknown site or no identity.
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
		if p.raw != nil {
			closeWAF(p.raw)
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
			raw, err := c.newWAF(c.directives(p.GetHostRules(), p.GetCrsSetup(), mode))
			if err != nil {
				return nil, fmt.Errorf("profile %s: %w", p.GetName(), err)
			}
			pw.raw, pw.waf = raw, siteWAF{raw}
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

// siteKey carries the request's site identity from the handler to siteWAF.
type siteKey struct{}

func withSite(ctx context.Context, site string) context.Context {
	return context.WithValue(ctx, siteKey{}, site)
}

// siteWAF adds the request's site identity to each transaction as request header
// bundle.SiteHeader. coraza's http.WrapHandler creates transactions through
// NewTransactionWithOptions with the request's context, which is where the handler put it. The
// header exists only inside the transaction; the handler removes any copy the client sent.
type siteWAF struct{ coraza.WAF }

func (w siteWAF) NewTransactionWithOptions(o experimental.Options) types.Transaction {
	var tx types.Transaction
	if wo, ok := w.WAF.(experimental.WAFWithOptions); ok {
		tx = wo.NewTransactionWithOptions(o)
	} else {
		tx = w.WAF.NewTransaction()
	}
	if o.Context != nil {
		if site, _ := o.Context.Value(siteKey{}).(string); site != "" {
			tx.AddRequestHeader(bundle.SiteHeader, site)
		}
	}
	return tx
}

var _ experimental.WAFWithOptions = siteWAF{}
