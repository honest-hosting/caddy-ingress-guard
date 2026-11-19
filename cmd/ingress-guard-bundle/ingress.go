package main

import (
	"errors"
	"flag"
	"fmt"
	"math"
	"math/rand/v2"
	"os"
	"slices"
	"strings"
	"time"

	"github.com/honest-hosting/caddy-ingress-guard/bundle"
	"github.com/honest-hosting/caddy-ingress-guard/bundle/bundlepb"
)

// S3 (Phase 02 §6.3): a synthetic ingress:<pool> bundle for N sites, in the hybrid layout under
// test: three base profiles, plus per-site exclusions as host_rules keyed on the site header.
//
// Site i is "h%05d.s3.test" with identity siteID(i); the spike Caddyfile maps one to the other,
// standing in for caddy-consul's consul_route_info. Sites 0-2 are probes, identical in every
// seed, so k6 can check profile selection and per-site exclusions while bundles swap:
//
//	site 0: pl1-enforce, no exclusions
//	site 1: pl1-detect
//	site 2: pl1-enforce, SQLi rules off for parameter hhprobe only
//
// The rest are random per seed: detect-pct% on pl1-detect, pl2-pct% on pl2-enforce, and
// excl-pct% with 1-3 exclusions. Half of those are a popular plugin's exclusion, shared by many
// sites; half are the site's own parameter, path or both. hostRules lays them out so that most
// requests evaluate almost none of them.

const (
	probeDetect   = 1
	probeExcluded = 2
	probeCount    = 3

	pl2SetupID = 19000001 // the pl2-enforce profile's crs_setup rule
	hostRuleID = 20000000 // host_rules IDs start above this
)

func siteID(i int) string { return fmt.Sprintf("00000000-0000-4000-8000-%012d", i) }

type exclusion struct {
	path string // "" for the whole site
	ctl  string
}

// Popular plugins' exclusions: the same on every site that has the plugin.
var sharedExclusions = []exclusion{
	{"", "ctl:ruleRemoveTargetById=942100;ARGS:content"},
	{"", "ctl:ruleRemoveTargetById=941160;ARGS:post_content"},
	{"/wp-admin/admin-ajax.php", "ctl:ruleRemoveTargetByTag=attack-sqli;ARGS:elementor_data"},
	{"/wp-admin/admin-ajax.php", "ctl:ruleRemoveTargetByTag=attack-xss;ARGS:elementor_data"},
	{"/wp-json/wc/store/", "ctl:ruleRemoveTargetById=942200;ARGS:data"},
	{"/wp-json/contact-form-7/", "ctl:ruleRemoveTargetById=932200;ARGS:your_message"},
	{"", "ctl:ruleRemoveTargetById=942430;ARGS:query"},
	{"", "ctl:ruleRemoveTargetById=920230;ARGS:_wp_http_referer"},
	{"/wp-json/wpforms/", "ctl:ruleRemoveTargetById=942440;ARGS:wpforms_fields"},
	{"/xmlrpc.php", "ctl:ruleRemoveById=942340"},
}

// A site's own exclusions: %s is a parameter only that site uses.
var ownTemplates = []string{
	"ctl:ruleRemoveTargetById=942100;ARGS:%s",
	"ctl:ruleRemoveTargetById=942200;ARGS:%s",
	"ctl:ruleRemoveTargetById=941160;ARGS:%s",
	"ctl:ruleRemoveTargetById=932200;ARGS:%s",
	"ctl:ruleRemoveTargetByTag=attack-sqli;ARGS:%s",
	"ctl:ruleRemoveTargetByTag=attack-xss;ARGS:%s",
}

var profileNames = []string{"pl1-enforce", "pl1-detect", "pl2-enforce"}

type genOptions struct {
	sites                      int
	seed                       uint64
	single                     bool
	exclPct, detectPct, pl2Pct float64
}

// genProfiles returns the profiles section and a one-line description of it.
func genProfiles(o genOptions) (*bundlepb.ProfilesSection, string) {
	ps := &bundlepb.ProfilesSection{DefaultProfile: profileNames[0], Sites: make(map[string]string, o.sites)}
	if o.single {
		ps.Profiles = []*bundlepb.Profile{{Name: profileNames[0]}}
		for i := range o.sites {
			ps.Sites[siteID(i)] = profileNames[0]
		}
		return ps, fmt.Sprintf("single profile %s for %d sites, no host rules", profileNames[0], o.sites)
	}

	rng := rand.New(rand.NewPCG(o.seed, 0))
	bySite := map[string]map[string][]exclusion{} // profile -> site -> its exclusions
	add := func(profile string, e exclusion, site string) {
		if bySite[profile] == nil {
			bySite[profile] = map[string][]exclusion{}
		}
		if !slices.Contains(bySite[profile][site], e) {
			bySite[profile][site] = append(bySite[profile][site], e)
		}
	}
	perProfile := map[string]int{}
	withExclusions := 0
	for i := range o.sites {
		site, profile := siteID(i), profileNames[0]
		if i == probeDetect {
			profile = profileNames[1]
		} else if i >= probeCount {
			switch r := rng.Float64() * 100; {
			case r < o.detectPct:
				profile = profileNames[1]
			case r < o.detectPct+o.pl2Pct:
				profile = profileNames[2]
			}
		}
		ps.Sites[site] = profile
		perProfile[profile]++
		if i == probeExcluded {
			add(profile, exclusion{ctl: "ctl:ruleRemoveTargetByTag=attack-sqli;ARGS:hhprobe"}, site)
			withExclusions++
			continue
		}
		if i < probeCount || rng.Float64()*100 >= o.exclPct {
			continue
		}
		withExclusions++
		for range 1 + rng.IntN(3) {
			e := sharedExclusions[rng.IntN(len(sharedExclusions))]
			if rng.IntN(2) == 0 {
				e.ctl = fmt.Sprintf(ownTemplates[rng.IntN(len(ownTemplates))], fmt.Sprintf("f_%06x", rng.IntN(1<<24)))
				e.path = ""
				if rng.IntN(2) == 0 {
					e.path = fmt.Sprintf("/wp-json/custom-%06x/", rng.IntN(1<<24))
				}
			}
			add(profile, e, site)
		}
	}

	id := hostRuleID
	var desc []string
	for _, name := range profileNames {
		p := &bundlepb.Profile{Name: name}
		switch name {
		case "pl1-detect":
			p.Mode = bundlepb.Mode_MODE_DETECT
		case "pl2-enforce":
			p.CrsSetup = fmt.Sprintf(`SecAction "id:%d,phase:1,pass,nolog,setvar:tx.blocking_paranoia_level=2,setvar:tx.detection_paranoia_level=2"`, pl2SetupID)
		}
		var rules, buckets int
		p.HostRules, rules, buckets = hostRules(bySite[name], &id)
		ps.Profiles = append(ps.Profiles, p)
		desc = append(desc, fmt.Sprintf("%s: %d sites, %d with exclusions, %d exclusion rules in %d buckets",
			name, perProfile[name], len(bySite[name]), rules, buckets))
	}
	return ps, fmt.Sprintf("%d sites, %d with exclusions; %s", o.sites, withExclusions, strings.Join(desc, "; "))
}

// hostRules compiles one profile's per-site exclusions into SecLang, laid out so a request
// evaluates as few rules as possible. Coraza costs a few µs per evaluated rule, and a SecMarker
// is phase 0: it is evaluated (as a forced match) in all five phases of every request. S3 found:
//
//   - run 2: one rule per exclusion, all evaluated on every request: +1.8 ms p50;
//   - run 2b: skipAfter gates, but a marker per bucket (24 markers x 5 phases): +1.2 ms p50.
//
// So, one marker only:
//
//   - two gates jump to the end marker for a request with no site identity, or whose site has
//     no exclusions (most requests);
//   - the sites with exclusions are split into about √n buckets. A bucket's gate skips the
//     bucket with skip:N, N being exact: the bucket's rules (a chain counts once) plus its
//     closing SecAction, which jumps to the end once the site's bucket has run.
//
// Every exclusion rule still matches the site itself, so the gates can only skip, never apply one
// site's exclusion to another. A wrong N in the last bucket would skip rules after host_rules
// (CRS setup), so N is computed, never written by hand. Within a bucket, sites sharing an
// exclusion share one rule.
func hostRules(bySite map[string][]exclusion, id *int) (seclang string, rules, buckets int) {
	if len(bySite) == 0 {
		return "", 0, 0
	}
	sites := make([]string, 0, len(bySite))
	for s := range bySite {
		sites = append(sites, s)
	}
	slices.Sort(sites)
	next := func() int { *id++; return *id }
	h := bundle.SiteHeader
	var sb strings.Builder
	fmt.Fprintf(&sb, "SecRule &REQUEST_HEADERS:%s \"@eq 0\" \"id:%d,phase:1,pass,nolog,skipAfter:IG_HOST_RULES_END\"\n", h, next())
	fmt.Fprintf(&sb, "SecRule REQUEST_HEADERS:%s \"!@pm %s\" \"id:%d,phase:1,pass,nolog,t:none,skipAfter:IG_HOST_RULES_END\"\n",
		h, strings.Join(sites, " "), next())
	size := int(math.Ceil(math.Sqrt(float64(len(sites)))))
	for start := 0; start < len(sites); start += size {
		bucket := sites[start:min(start+size, len(sites))]
		buckets++
		groups := map[exclusion][]string{}
		for _, s := range bucket {
			for _, e := range bySite[s] {
				groups[e] = append(groups[e], s)
			}
		}
		exs := make([]exclusion, 0, len(groups))
		for e := range groups {
			exs = append(exs, e)
		}
		slices.SortFunc(exs, func(a, b exclusion) int { return strings.Compare(a.path+" "+a.ctl, b.path+" "+b.ctl) })
		// skip: this bucket's rules (one per exclusion, a chain counting once) and its SecAction.
		fmt.Fprintf(&sb, "SecRule REQUEST_HEADERS:%s \"!@pm %s\" \"id:%d,phase:1,pass,nolog,t:none,skip:%d\"\n",
			h, strings.Join(bucket, " "), next(), len(exs)+1)
		for _, e := range exs {
			who := strings.Join(groups[e], " ")
			if e.path == "" {
				fmt.Fprintf(&sb, "SecRule REQUEST_HEADERS:%s \"@pm %s\" \"id:%d,phase:1,pass,nolog,t:none,%s\"\n", h, who, next(), e.ctl)
			} else {
				fmt.Fprintf(&sb, "SecRule REQUEST_HEADERS:%s \"@pm %s\" \"id:%d,phase:1,pass,nolog,t:none,chain\"\n\tSecRule REQUEST_FILENAME \"@beginsWith %s\" \"t:none,%s\"\n",
					h, who, next(), e.path, e.ctl)
			}
			rules++
		}
		fmt.Fprintf(&sb, "SecAction \"id:%d,phase:1,pass,nolog,skipAfter:IG_HOST_RULES_END\"\n", next())
	}
	sb.WriteString("SecMarker IG_HOST_RULES_END\n")
	return sb.String(), rules, buckets
}

// ingress writes one synthetic ingress bundle, or with -count is the S3 agent stub: it pushes a
// fresh bundle every interval, alternating seeds -seed and -seed+1, so every push changes the
// per-site rules and the module rebuilds every profile.
func ingress(args []string) error {
	fl := flag.NewFlagSet("ingress", flag.ExitOnError)
	var bf buildFlags
	bf.register(fl)
	var o genOptions
	fl.IntVar(&o.sites, "sites", 5000, "synthetic sites")
	fl.Uint64Var(&o.seed, "seed", 1, "random seed for profiles and exclusions (sites 0-2 never change)")
	fl.BoolVar(&o.single, "single", false, "one profile for every site and no host rules (the baseline)")
	fl.Float64Var(&o.exclPct, "excl-pct", 9, "percent of sites with 1-3 exclusions")
	fl.Float64Var(&o.detectPct, "detect-pct", 1, "percent of sites on detection-only")
	fl.Float64Var(&o.pl2Pct, "pl2-pct", 1, "percent of sites on paranoia level 2")
	out := fl.String("out", "ingress.pb", "output file (without -count)")
	url := fl.String("url", "http://127.0.0.1:2020/v1/bundle", "push endpoint (with -count)")
	every := fl.Duration("every", 10*time.Second, "push interval (with -count)")
	count := fl.Int("count", 0, "push this many bundles instead of writing -out")
	_ = fl.Parse(args)
	if o.sites < probeCount {
		return fmt.Errorf("-sites must be at least %d", probeCount)
	}
	if !strings.HasPrefix(bf.target, bundle.TargetIngressPrefix) {
		return errors.New("-target must be ingress:<pool>")
	}
	b, err := newBuilder(bf)
	if err != nil {
		return err
	}
	withProfiles := func(seed uint64) string {
		o := o
		o.seed = seed
		ps, desc := genProfiles(o)
		b.extra = []bundle.SectionInput{{Name: bundle.SectionProfiles, Required: true, Body: ps}}
		return desc
	}

	if *count > 0 {
		fmt.Fprintln(os.Stderr, withProfiles(o.seed))
		fmt.Fprintln(os.Stderr, withProfiles(o.seed+1))
		return pushLoop(*url, *every, *count, func(i int) (string, []byte, *bundlepb.Manifest, error) {
			seed := o.seed + uint64(i%2)
			withProfiles(seed)
			raw, m, err := b.build("")
			return fmt.Sprintf("seed%d", seed), raw, m, err
		})
	}
	desc := withProfiles(o.seed)
	raw, m, err := b.build("")
	if err != nil {
		return err
	}
	fmt.Printf("%s: target=%s sequence=%d bytes=%d (payload decompressed %d)\n%s\n",
		*out, m.GetTarget(), m.GetSequence(), len(raw), m.GetPayloadSize(), desc)
	return os.WriteFile(*out, raw, 0o644)
}
