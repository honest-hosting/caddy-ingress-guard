package ingressguard

import (
	"fmt"
	"io/fs"
	"sort"
	"strings"
	"testing/fstest"

	"github.com/corazawaf/coraza/v3"
	"google.golang.org/protobuf/proto"

	"github.com/honest-hosting/caddy-ingress-guard/bundle"
	"github.com/honest-hosting/caddy-ingress-guard/bundle/bundlepb"
)

// crsRoot is where bundle CRS files appear in the WAF's in-memory root filesystem.
const crsRoot = "crs"

// composed is the layers' SecLang slots and CRS filesystem. directives turns it into one WAF
// instance's SecLang: one in site mode, one per profile in multi mode.
type composed struct {
	pre, crsSetup, post string        // every layer's slot, in layer order
	fsys                fs.FS         // CRS files, or nil
	includes            []string      // Include lines for the CRS files, in load order
	mode                bundlepb.Mode // from switches; the most specific layer wins
	profiles            *bundlepb.ProfilesSection
}

// Engine defaults come first so bundles can override them; the switches section's engine mode
// is applied last so it stays authoritative.
const engineDefaults = `SecRequestBodyAccess On
SecResponseBodyAccess Off
SecRequestBodyLimit 13107200
SecRequestBodyInMemoryLimit 131072
SecRequestBodyLimitAction ProcessPartial
SecAuditEngine Off
`

// compose orders the layers (global, DC, site) for assembly per A1 §2:
//
//	global pre → DC pre → site pre (exclusions) → CRS setup + CRS → global post → DC post → site post
//
// The ingress tier has a single layer (its pool's bundle), which also carries the profiles.
func compose(layers map[string]*layer) (*composed, error) {
	ordered := make([]*layer, 0, len(layers))
	for _, l := range layers {
		ordered = append(ordered, l)
	}
	sort.Slice(ordered, func(i, j int) bool {
		ri, rj := bundle.LayerRank(ordered[i].target), bundle.LayerRank(ordered[j].target)
		if ri != rj {
			return ri < rj
		}
		return ordered[i].target < ordered[j].target
	})

	mode := bundlepb.Mode_MODE_ENFORCE
	corazas := make([]*bundlepb.CorazaSection, 0, len(ordered))
	var crs *bundlepb.CrsSection
	var profiles *bundlepb.ProfilesSection
	for _, l := range ordered {
		if b := bundle.Section(l.payload, bundle.SectionProfiles); b != nil {
			ps := &bundlepb.ProfilesSection{}
			if err := proto.Unmarshal(b, ps); err != nil {
				return nil, fmt.Errorf("%s: profiles: %w", l.target, err)
			}
			profiles = ps
		}
		if b := bundle.Section(l.payload, bundle.SectionSwitches); b != nil {
			sw := &bundlepb.SwitchesSection{}
			if err := proto.Unmarshal(b, sw); err != nil {
				return nil, fmt.Errorf("%s: switches: %w", l.target, err)
			}
			if sw.GetMode() != bundlepb.Mode_MODE_UNSPECIFIED {
				mode = sw.GetMode() // the more specific layer wins
			}
		}
		if b := bundle.Section(l.payload, bundle.SectionCoraza); b != nil {
			cz := &bundlepb.CorazaSection{}
			if err := proto.Unmarshal(b, cz); err != nil {
				return nil, fmt.Errorf("%s: coraza: %w", l.target, err)
			}
			corazas = append(corazas, cz)
		}
		if b := bundle.Section(l.payload, bundle.SectionCRS); b != nil && crs == nil {
			c := &bundlepb.CrsSection{}
			if err := proto.Unmarshal(b, c); err != nil {
				return nil, fmt.Errorf("%s: crs: %w", l.target, err)
			}
			crs = c // the least specific layer that carries CRS (global, or the ingress bundle)
		}
	}
	c := &composed{mode: mode, profiles: profiles}
	if mode == bundlepb.Mode_MODE_OFF {
		return c, nil
	}
	var pre, setup, post strings.Builder
	for _, cz := range corazas {
		writeSlot(&pre, cz.GetPre())
		writeSlot(&setup, cz.GetCrsSetup())
		writeSlot(&post, cz.GetPost())
	}
	c.pre, c.crsSetup, c.post = pre.String(), setup.String(), post.String()

	if crs != nil {
		switch src := crs.GetSource().(type) {
		case *bundlepb.CrsSection_Files:
			mfs, includes, err := crsFS(src.Files.GetFiles())
			if err != nil {
				return nil, err
			}
			c.fsys, c.includes = mfs, includes
		case *bundlepb.CrsSection_EmbeddedVersion:
			return nil, fmt.Errorf("embedded CRS %q is not compiled into this build", src.EmbeddedVersion)
		}
	}
	return c, nil
}

// directives assembles one WAF instance's SecLang. hostRules and profileSetup are a multi-mode
// profile's slots (empty in site mode); exclusions stay ahead of CRS (Phase 01 §11).
func (c *composed) directives(hostRules, profileSetup string, mode bundlepb.Mode) string {
	var sb strings.Builder
	sb.WriteString(engineDefaults)
	writeSlot(&sb, c.pre)
	writeSlot(&sb, hostRules)
	writeSlot(&sb, c.crsSetup)
	writeSlot(&sb, profileSetup)
	for _, inc := range c.includes {
		sb.WriteString("Include " + inc + "\n")
	}
	writeSlot(&sb, c.post)
	if mode == bundlepb.Mode_MODE_DETECT {
		sb.WriteString("SecRuleEngine DetectionOnly\n")
	} else {
		sb.WriteString("SecRuleEngine On\n")
	}
	return sb.String()
}

// newWAF builds one WAF instance from directives, with the CRS files as its root filesystem.
func (c *composed) newWAF(directives string) (coraza.WAF, error) {
	maybePanicBuild(directives)
	cfg := coraza.NewWAFConfig().WithDirectives(directives)
	if c.fsys != nil {
		cfg = cfg.WithRootFS(c.fsys)
	}
	return coraza.NewWAF(cfg)
}

func writeSlot(sb *strings.Builder, s string) {
	if strings.TrimSpace(s) == "" {
		return
	}
	sb.WriteString(s)
	if !strings.HasSuffix(s, "\n") {
		sb.WriteByte('\n')
	}
}

// crsFS turns bundle CRS files into an in-memory root filesystem for Coraza's WithRootFS, and
// returns the Include lines in CRS 4's load order (plugins config → before → rules → after).
// Both CRS's own layout (rules/, plugins/) and a flat directory of rule files (central's
// infrastructure/habitat/caddy/owasp) work; CRS setup belongs in the coraza crs_setup slot, not
// among the files. Rule files are never written to disk.
func crsFS(files map[string][]byte) (fs.FS, []string, error) {
	m := fstest.MapFS{}
	for p, data := range files {
		full := crsRoot + "/" + p
		if !fs.ValidPath(full) || strings.Contains(p, "..") {
			return nil, nil, fmt.Errorf("crs: invalid path %q", p)
		}
		m[full] = &fstest.MapFile{Data: data, Mode: 0o444}
	}
	var includes []string
	for _, pattern := range []string{
		crsRoot + "/plugins/*-config.conf",
		crsRoot + "/plugins/*-before.conf",
		crsRoot + "/rules/*.conf",
		crsRoot + "/*.conf", // flat layout
		crsRoot + "/plugins/*-after.conf",
	} {
		matches, err := fs.Glob(m, pattern)
		if err != nil {
			return nil, nil, err
		}
		if len(matches) > 0 {
			includes = append(includes, pattern)
		}
	}
	if len(includes) == 0 {
		return nil, nil, fmt.Errorf("crs: no rule files")
	}
	return m, includes, nil
}
