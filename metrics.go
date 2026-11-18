package ingressguard

import "github.com/prometheus/client_golang/prometheus"

// metrics are owned by the runtime (they survive reloads) and registered into each config's
// Caddy metrics registry.
type metrics struct {
	active          *prometheus.GaugeVec
	expires         *prometheus.GaugeVec
	unprotected     prometheus.Gauge
	panics          *prometheus.CounterVec
	activation      prometheus.Histogram
	rejected        *prometheus.CounterVec
	pushes          *prometheus.CounterVec
	requests        *prometheus.CounterVec
	profileRequests *prometheus.CounterVec
	skippedSections *prometheus.CounterVec
}

func newMetrics() *metrics {
	return &metrics{
		active: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Name: "ingress_guard_bundle_active",
			Help: "Active bundle sequence per target (layer).",
		}, []string{"target"}),
		expires: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Name: "ingress_guard_bundle_expires_timestamp_seconds",
			Help: "Expiry of the active bundle per target, unix seconds.",
		}, []string{"target"}),
		unprotected: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "ingress_guard_unprotected",
			Help: "1 while no bundle is active (serving open).",
		}),
		panics: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "ingress_guard_panics_total",
			Help: "Recovered panics, by where (request, build).",
		}, []string{"where"}),
		activation: prometheus.NewHistogram(prometheus.HistogramOpts{
			Name:    "ingress_guard_activation_seconds",
			Help:    "Time from push received to the new bundle serving (verify + build + swap).",
			Buckets: []float64{.01, .05, .1, .25, .5, 1, 2, 5, 10, 15, 30},
		}),
		rejected: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "ingress_guard_rejected_total",
			Help: "Rejected pushes, by reason.",
		}, []string{"reason"}),
		pushes: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "ingress_guard_pushes_total",
			Help: "Bundle pushes, by result.",
		}, []string{"result"}),
		requests: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "ingress_guard_requests_total",
			Help: "Requests at the inspect stage, by result (inspected, unprotected, off).",
		}, []string{"result"}),
		profileRequests: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "ingress_guard_profile_requests_total",
			Help: "Multi mode: requests at the inspect stage, by the profile their site uses.",
		}, []string{"profile"}),
		skippedSections: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "ingress_guard_skipped_sections_total",
			Help: "Optional bundle sections this build skipped, by name.",
		}, []string{"section"}),
	}
}

func (m *metrics) collectors() []prometheus.Collector {
	return []prometheus.Collector{
		m.active, m.expires, m.unprotected, m.panics, m.activation,
		m.rejected, m.pushes, m.requests, m.profileRequests, m.skippedSections,
	}
}
