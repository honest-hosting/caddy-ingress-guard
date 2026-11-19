package ingressguard

import (
	"bytes"
	"context"
	"fmt"
	"maps"
	"net/http"
	"sort"
	"sync"
	"sync/atomic"
	"time"

	"github.com/corazawaf/coraza/v3"
	"github.com/corazawaf/coraza/v3/experimental"
	"go.uber.org/zap"

	"github.com/honest-hosting/caddy-ingress-guard/bundle"
	"github.com/honest-hosting/caddy-ingress-guard/bundle/bundlepb"
)

// Sections this build understands.
var knownSections = map[string]bool{
	bundle.SectionCoraza:         true,
	bundle.SectionCRS:            true,
	bundle.SectionSwitches:       true,
	bundle.SectionTrustedProxies: true,
	bundle.SectionProfiles:       true,
}

type runtimeConfig struct {
	mode           string
	targets        map[string]bool
	verifier       *bundle.Verifier
	staleBootstrap bool
	pushListen     string
}

// layer is one accepted bundle for one target. Immutable once stored in a snapshot.
type layer struct {
	target   string
	manifest *bundlepb.Manifest
	payload  *bundlepb.Payload
	stale    bool // accepted although expired (stale bootstrap)
}

// engines is what a build produces: one WAF (site mode) or one per profile (multi mode).
type engines struct {
	waf   coraza.WAF // site mode; nil: no WAF (open, or mode off)
	multi *multiSet  // multi mode
	off   bool       // mode off by policy (deliberately open)
}

// snapshot is what requests read. It is immutable after Store: a concurrent map write is a Go
// fatal error that recover() cannot catch, so nothing here is ever mutated in place.
type snapshot struct {
	engines
	layers  map[string]*layer
	pending map[string]*layer // waiting for a layer constraint; not active
	builtAt time.Time
}

func (s *snapshot) unprotected() bool {
	return s == nil || (s.waf == nil && s.multi == nil && !s.off)
}

type runtime struct {
	logger  atomic.Pointer[zap.Logger]
	cfg     atomic.Pointer[runtimeConfig]
	active  atomic.Pointer[snapshot]
	metrics *metrics

	buildMu   sync.Mutex    // serializes accept + build + swap
	pushSlots chan struct{} // push endpoint concurrency (push.go admit)

	srvMu   sync.Mutex
	srv     *http.Server
	srvAddr string
}

func newRuntime() *runtime {
	rt := &runtime{
		metrics:   newMetrics(),
		pushSlots: make(chan struct{}, pushConcurrency),
	}
	rt.logger.Store(zap.NewNop())
	rt.metrics.unprotected.Set(1)
	return rt
}

func (rt *runtime) setForceDetect(on bool) {
	if on {
		rt.metrics.forceDetect.Set(1)
	} else {
		rt.metrics.forceDetect.Set(0)
	}
}

func (rt *runtime) setLogger(l *zap.Logger)      { rt.logger.Store(l) }
func (rt *runtime) log() *zap.Logger             { return rt.logger.Load() }
func (rt *runtime) configure(cfg *runtimeConfig) { rt.cfg.Store(cfg) }
func (rt *runtime) snapshot() *snapshot          { return rt.active.Load() }

// Destruct stops the push endpoint and closes the active WAF when the last app lets go of the
// runtime.
func (rt *runtime) Destruct() error {
	rt.buildMu.Lock()
	if prev := rt.active.Swap(nil); prev != nil {
		if prev.waf != nil {
			closeWAF(prev.waf)
		}
		prev.multi.close()
	}
	rt.buildMu.Unlock()

	rt.srvMu.Lock()
	defer rt.srvMu.Unlock()
	if rt.srv == nil {
		return nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	err := rt.srv.Shutdown(ctx)
	rt.srv = nil
	return err
}

// loadStatic builds the WAF from Caddy config (static mode).
func (rt *runtime) loadStatic(directives, file string) error {
	waf, err := buildStatic(directives, file)
	if err != nil {
		return err
	}
	rt.buildMu.Lock()
	defer rt.buildMu.Unlock()
	rt.store(&snapshot{engines: engines{waf: waf}, layers: map[string]*layer{}, builtAt: time.Now()})
	return nil
}

// buildStatic builds a WAF from SecLang in Caddy config: static mode, and handlers with their own
// static rules (DR-03). The directives come first, then the file; Include paths resolve on the
// local filesystem. The rules are used as given: no engine defaults are added.
func buildStatic(directives, file string) (coraza.WAF, error) {
	cfg := coraza.NewWAFConfig()
	if directives != "" {
		cfg = cfg.WithDirectives(directives)
	}
	if file != "" {
		cfg = cfg.WithDirectivesFromFile(file)
	}
	waf, err := coraza.NewWAF(cfg)
	if err != nil {
		return nil, fmt.Errorf("ingress_guard: static rules: %w", err)
	}
	return waf, nil
}

// closeWAF releases a replaced WAF's share of Coraza's pattern cache.
//
// Coraza (3.8.1) memoizes compiled regex and Aho-Corasick patterns in a process-wide cache by
// default, and records every WAF that uses each entry. An entry is only released when all of
// its WAFs are closed, so a WAF that is swapped out but never closed leaks its owner ID on every
// pattern it used. S2 run 2 measured about 14 KiB of live heap per swap with CRS loaded.
// coraza-caddy closes its WAFs for the same reason. Closing straight after the swap is safe:
// in-flight transactions keep their own references to the compiled patterns.
func closeWAF(w coraza.WAF) {
	if c, ok := w.(experimental.WAFCloser); ok {
		_ = c.Close()
	}
}

// submitResult is the outcome of one push.
type submitResult struct {
	ack    *bundlepb.Ack
	status int
}

func (rt *runtime) rejected(start time.Time, err error) submitResult {
	reason := bundle.ReasonOf(err)
	rt.metrics.rejected.WithLabelValues(reason).Inc()
	status := http.StatusUnprocessableEntity
	switch reason {
	case bundle.ReasonTooLarge:
		status = http.StatusRequestEntityTooLarge
	case bundle.ReasonOldSequence:
		status = http.StatusConflict
	case bundle.ReasonRateLimited:
		status = http.StatusTooManyRequests
	}
	ack := rt.ackFor(rt.snapshot())
	ack.Accepted = false
	ack.Reason = reason
	ack.Detail = err.Error()
	ack.ActivationMs = time.Since(start).Milliseconds()
	return submitResult{ack: ack, status: status}
}

// Submit verifies a pushed bundle and, if it is valid and newer, activates it (A1 §4.2 order).
func (rt *runtime) Submit(raw []byte) submitResult {
	start := time.Now()
	cfg := rt.cfg.Load()
	if cfg == nil || cfg.verifier == nil {
		return rt.rejected(start, &bundle.Error{Reason: bundle.ReasonWrongTarget, Detail: "module not accepting bundles"})
	}

	// 1-2: size caps, parse, cheap rejects. Nothing is trusted yet.
	p, err := bundle.Peek(raw)
	if err != nil {
		return rt.rejected(start, err)
	}
	m := p.Manifest
	if !cfg.targets[m.GetTarget()] {
		return rt.rejected(start, &bundle.Error{Reason: bundle.ReasonWrongTarget, Detail: m.GetTarget()})
	}
	if err := checkNewer(rt.snapshot(), m); err != nil {
		return rt.rejected(start, err)
	}

	// 3-4: signatures, then time window.
	if _, err := cfg.verifier.Verify(p); err != nil {
		return rt.rejected(start, err)
	}
	snap := rt.snapshot()
	_, hasActive := snap.layerFor(m.GetTarget())
	expired, err := cfg.verifier.CheckTime(p, cfg.staleBootstrap && !hasActive)
	if err != nil {
		return rt.rejected(start, err)
	}

	// 5-7: payload hash, decompress, sections.
	pl, skipped, err := bundle.OpenPayload(p, knownSections, ModuleVersion)
	if err != nil {
		return rt.rejected(start, err)
	}
	for _, s := range skipped {
		rt.metrics.skippedSections.WithLabelValues(s).Inc()
	}

	// 8: build and swap, one at a time.
	rt.buildMu.Lock()
	defer rt.buildMu.Unlock()

	snap = rt.snapshot()
	if err := checkNewer(snap, m); err != nil { // re-check: another push may have won the race
		return rt.rejected(start, err)
	}
	nl := &layer{target: m.GetTarget(), manifest: m, payload: pl, stale: expired}

	// A refresh of unchanged content only replaces the manifest (new sequence and expiry).
	if cur, ok := snap.layerFor(nl.target); ok && bytes.Equal(cur.manifest.GetPayloadSha256(), m.GetPayloadSha256()) {
		next := snap.with(func(s *snapshot) { s.layers[nl.target] = nl })
		rt.store(next)
		return rt.accepted(start, next)
	}

	layers := cloneLayers(snap.activeLayers())
	pending := cloneLayers(snap.pendingLayers())
	delete(pending, nl.target)
	layers[nl.target] = nl
	if unmet := unmetConstraint(nl, layers); unmet != "" {
		// Wait for the layer; the previous bundle for this target stays active.
		delete(layers, nl.target)
		if old, ok := snap.layerFor(nl.target); ok {
			layers[nl.target] = old
		}
		pending[nl.target] = nl
		next := &snapshot{engines: snap.enginesOrZero(), layers: layers, pending: pending, builtAt: snap.builtAtOrZero()}
		rt.store(next)
		res := rt.accepted(start, next)
		res.ack.Detail = "pending layer " + unmet
		return res
	}
	// A layer that just arrived may release pending ones.
	for t, pl := range pending {
		if unmetConstraint(pl, layers) == "" {
			layers[t] = pl
			delete(pending, t)
		}
	}

	e, err := rt.build(layers, cfg.mode == ModeMulti)
	if err != nil {
		return rt.rejected(start, &bundle.Error{Reason: bundle.ReasonBuildFailed, Detail: err.Error()})
	}
	next := &snapshot{engines: e, layers: layers, pending: pending, builtAt: time.Now()}
	rt.store(next)
	rt.metrics.activation.Observe(time.Since(start).Seconds())
	return rt.accepted(start, next)
}

func (rt *runtime) accepted(start time.Time, s *snapshot) submitResult {
	ack := rt.ackFor(s)
	ack.Accepted = true
	ack.ActivationMs = time.Since(start).Milliseconds()
	rt.metrics.pushes.WithLabelValues("accepted").Inc()
	return submitResult{ack: ack, status: http.StatusOK}
}

// store swaps the active snapshot, closes the WAFs it replaced (see closeWAF) and updates the
// gauges. Callers hold buildMu. A refresh or a pending-layer change reuses the active WAFs, so
// those are not closed.
func (rt *runtime) store(s *snapshot) {
	if prev := rt.active.Swap(s); prev != nil {
		if prev.waf != nil && prev.waf != s.waf {
			closeWAF(prev.waf)
		}
		if prev.multi != s.multi {
			prev.multi.close()
		}
	}
	if s.unprotected() {
		rt.metrics.unprotected.Set(1)
	} else {
		rt.metrics.unprotected.Set(0)
	}
	rt.metrics.active.Reset()
	rt.metrics.expires.Reset()
	for t, l := range s.layers {
		rt.metrics.active.WithLabelValues(t).Set(float64(l.manifest.GetSequence()))
		rt.metrics.expires.WithLabelValues(t).Set(float64(l.manifest.GetExpiresAt()))
	}
}

// build composes the layers and builds new WAF instances (one, or one per profile in multi mode),
// recovering from panics: a failed build leaves the previous instances active.
func (rt *runtime) build(layers map[string]*layer, multi bool) (e engines, err error) {
	defer func() {
		if r := recover(); r != nil {
			rt.metrics.panics.WithLabelValues("build").Inc()
			rt.log().Error("ingress_guard: panic during bundle build", zap.Any("panic", r))
			e, err = engines{}, fmt.Errorf("panic: %v", r)
		}
	}()
	c, err := compose(layers)
	if err != nil {
		return engines{}, err
	}
	if c.mode == bundlepb.Mode_MODE_OFF {
		return engines{off: true}, nil
	}
	if multi {
		set, err := c.buildProfiles()
		return engines{multi: set}, err
	}
	waf, err := c.newWAF(c.directives("", "", c.mode))
	return engines{waf: waf}, err
}

// checkNewer rejects a sequence that is not newer than the active (or pending) one.
func checkNewer(s *snapshot, m *bundlepb.Manifest) error {
	for _, set := range []map[string]*layer{s.activeLayers(), s.pendingLayers()} {
		if cur, ok := set[m.GetTarget()]; ok && m.GetSequence() <= cur.manifest.GetSequence() {
			return &bundle.Error{Reason: bundle.ReasonOldSequence,
				Detail: fmt.Sprintf("%d <= %d", m.GetSequence(), cur.manifest.GetSequence())}
		}
	}
	return nil
}

// unmetConstraint returns the first layer constraint not satisfied by layers, or "".
func unmetConstraint(l *layer, layers map[string]*layer) string {
	for _, c := range l.manifest.GetLayerConstraints() {
		have, ok := layers[c.GetTarget()]
		if !ok || have.manifest.GetSequence() < c.GetMinSequence() {
			return fmt.Sprintf("%s>=%d", c.GetTarget(), c.GetMinSequence())
		}
	}
	return ""
}

func (s *snapshot) activeLayers() map[string]*layer {
	if s == nil {
		return nil
	}
	return s.layers
}

func (s *snapshot) pendingLayers() map[string]*layer {
	if s == nil {
		return nil
	}
	return s.pending
}

func (s *snapshot) layerFor(t string) (*layer, bool) {
	if s == nil {
		return nil, false
	}
	l, ok := s.layers[t]
	return l, ok
}

// eventLayer is the layer a WAF event names: the most specific active one (the ingress bundle in
// multi mode, site over DC over global in site mode). Nil when nothing is active.
func (s *snapshot) eventLayer() *layer {
	var best *layer
	for _, l := range s.activeLayers() {
		if best == nil {
			best = l
			continue
		}
		rl, rb := bundle.LayerRank(l.target), bundle.LayerRank(best.target)
		if rl > rb || (rl == rb && l.target > best.target) {
			best = l
		}
	}
	return best
}

func (s *snapshot) enginesOrZero() engines {
	if s == nil {
		return engines{}
	}
	return s.engines
}

func (s *snapshot) builtAtOrZero() time.Time {
	if s == nil {
		return time.Time{}
	}
	return s.builtAt
}

// with returns a copy of s (maps cloned) after applying fn to the copy.
func (s *snapshot) with(fn func(*snapshot)) *snapshot {
	c := &snapshot{engines: s.engines, builtAt: s.builtAt,
		layers: cloneLayers(s.layers), pending: cloneLayers(s.pending)}
	fn(c)
	return c
}

func cloneLayers(m map[string]*layer) map[string]*layer {
	if m == nil {
		return map[string]*layer{}
	}
	return maps.Clone(m)
}

// ackFor reports every active and pending layer, sorted global → DC → site.
func (rt *runtime) ackFor(s *snapshot) *bundlepb.Ack {
	return &bundlepb.Ack{Layers: layerStatuses(s), ModuleVersion: ModuleVersion}
}

func layerStatuses(s *snapshot) []*bundlepb.LayerStatus {
	var out []*bundlepb.LayerStatus
	add := func(l *layer, state bundlepb.LayerState) {
		out = append(out, &bundlepb.LayerStatus{
			Target:        l.target,
			Sequence:      l.manifest.GetSequence(),
			PayloadSha256: l.manifest.GetPayloadSha256(),
			ExpiresAt:     l.manifest.GetExpiresAt(),
			State:         state,
			BundleId:      l.manifest.GetBundleId(),
		})
	}
	for _, l := range s.activeLayers() {
		st := bundlepb.LayerState_LAYER_STATE_ACTIVE
		if l.stale {
			st = bundlepb.LayerState_LAYER_STATE_STALE
		}
		add(l, st)
	}
	for _, l := range s.pendingLayers() {
		add(l, bundlepb.LayerState_LAYER_STATE_PENDING_LAYER)
	}
	sort.Slice(out, func(i, j int) bool {
		ri, rj := bundle.LayerRank(out[i].Target), bundle.LayerRank(out[j].Target)
		if ri != rj {
			return ri < rj
		}
		if out[i].Target != out[j].Target {
			return out[i].Target < out[j].Target
		}
		return out[i].State < out[j].State
	})
	return out
}

// Status reports the active state (GET /v1/status). It never includes secrets.
func (rt *runtime) Status() *bundlepb.Status {
	s := rt.snapshot()
	return &bundlepb.Status{
		Layers:        layerStatuses(s),
		ModuleVersion: ModuleVersion,
		Unprotected:   s.unprotected(),
		ReportedAt:    time.Now().Unix(),
	}
}
