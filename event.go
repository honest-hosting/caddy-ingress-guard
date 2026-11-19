package ingressguard

import (
	"net/http"
	"strconv"

	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"github.com/corazawaf/coraza/v3/types"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

// WAF events: one log line per transaction that matched a logged rule or was (or would have
// been) interrupted, on the handler's logger named "event" (http.handlers.ingress_guard.event).
// Log shipping keys on these names, so they are a contract: keep them stable and snake_case.
//
//	msg         "waf event"
//	action      block | would_block | detect
//	mode        static | multi | site (what drove the rules: a static handler, or the app's mode)
//	tx_id       the WAF transaction ID (tx_id_header, else Caddy's request UUID)
//	request_id  Caddy's request UUID ({http.request.uuid})
//	site        the route's site identity (multi) or the site's UUID (site mode); omitted if none
//	tenant      the tenant_identity placeholder's value; omitted if none
//	profile     the multi-mode profile; omitted otherwise
//	target      the bundle target the rules came from (most specific active layer); omitted for static
//	sequence    that bundle's sequence; omitted for static
//	rule_id     the interrupting rule (block, would_block); omitted for detect
//	status      the HTTP status of the (would-be) block; omitted for detect
//	forced      true when force_mode detect turned a block into would_block; omitted otherwise
//	rule_ids    every logged rule that matched, in match order
//	severity    the highest severity among them ("" if none set)
//	message     the interrupting rule's message, else the highest-severity rule's
//	host, method, uri, client_ip
//
// would_block is the shadow signal: a detect profile, a pool-wide detect switch, force_mode or a
// per-request ctl:ruleEngine=DetectionOnly would have blocked this request.
//
// The same action and rule ID are set as Caddy vars ingress_guard.action and
// ingress_guard.rule_id, for access logs ({http.vars.ingress_guard.action}).
const (
	ActionBlock      = "block"
	ActionWouldBlock = "would_block"
	ActionDetect     = "detect"
)

const eventMessage = "waf event"

// detectionOnly is the part of Coraza's transaction that records, in DetectionOnly mode, the
// interruption an enforcing engine would have made (Coraza 3.4+; not in the public interface).
type detectionOnly interface {
	DetectionOnlyInterruption() *types.Interruption
}

// classify decides the event's action. A real interruption is a block, unless force_mode served
// the request anyway; a DetectionOnly transaction's recorded interruption is a would_block.
func classify(tx types.Transaction, forced bool) (action string, it *types.Interruption, wasForced bool) {
	if it := tx.Interruption(); it != nil {
		if forced {
			return ActionWouldBlock, it, true
		}
		return ActionBlock, it, false
	}
	if d, ok := tx.(detectionOnly); ok {
		if it := d.DetectionOnlyInterruption(); it != nil {
			return ActionWouldBlock, it, false
		}
	}
	return "", nil, false
}

// matched summarizes the logged rules that matched (nolog rules, such as CRS initialization and
// host_rules exclusions, are left out; the interrupting rule is always kept).
func matched(tx types.Transaction, it *types.Interruption) (ids []int, severity, message string) {
	best := types.RuleSeverityUnset
	var bestMsg, itMsg string
	for _, mr := range tx.MatchedRules() {
		rule := mr.Rule()
		id := rule.ID()
		isIt := it != nil && id == it.RuleID
		if l, ok := mr.(interface{ Log() bool }); ok && !l.Log() && !isIt {
			continue
		}
		if isIt && itMsg == "" {
			itMsg = mr.Message()
		}
		if s := rule.Severity(); s != types.RuleSeverityUnset && (best == types.RuleSeverityUnset || s < best) {
			best, bestMsg = s, mr.Message()
		}
		dup := false
		for _, seen := range ids {
			if seen == id {
				dup = true
				break
			}
		}
		if !dup {
			ids = append(ids, id)
		}
	}
	if best != types.RuleSeverityUnset {
		severity = best.String()
	}
	message = itMsg
	if message == "" {
		message = bestMsg
	}
	return ids, severity, message
}

// report writes the transaction's event line, counts interruptions and sets the Caddy vars. It
// runs after the response phases, so a detect line also covers response-header rules.
func (h *Handler) report(r *http.Request, tx types.Transaction, in *inspection) {
	action, it, forced := classify(tx, in.forced)
	ids, severity, message := matched(tx, it)
	if action == "" {
		if len(ids) == 0 {
			return
		}
		action = ActionDetect
	}
	ruleID := 0
	if it != nil {
		ruleID = it.RuleID
		h.app.rt.metrics.interruptions.WithLabelValues(action, in.mode, in.profile).Inc()
	}
	caddyhttp.SetVar(r.Context(), "ingress_guard.action", action)
	if ruleID != 0 {
		caddyhttp.SetVar(r.Context(), "ingress_guard.rule_id", strconv.Itoa(ruleID))
	}

	level := zapcore.InfoLevel
	if action == ActionBlock {
		level = zapcore.WarnLevel
	}
	ce := h.events.Check(level, eventMessage)
	if ce == nil {
		return
	}
	fields := make([]zap.Field, 0, 20)
	fields = append(fields,
		zap.String("action", action),
		zap.String("mode", in.mode),
		zap.String("tx_id", tx.ID()),
	)
	if rid := requestUUID(r); rid != "" {
		fields = append(fields, zap.String("request_id", rid))
	}
	site := in.site
	if site == "" && h.app.Mode == ModeMulti {
		site = h.siteIdentity(r) // a static handler on a route that has an identity
	}
	if site != "" {
		fields = append(fields, zap.String("site", site))
	}
	if tenant := resolve(r, h.app.TenantIdentity); tenant != "" {
		fields = append(fields, zap.String("tenant", tenant))
	}
	if in.profile != "" {
		fields = append(fields, zap.String("profile", in.profile))
	}
	if l := in.snap.eventLayer(); l != nil && in.mode != ModeStatic {
		fields = append(fields, zap.String("target", l.target), zap.Uint64("sequence", l.manifest.GetSequence()))
	}
	if it != nil {
		fields = append(fields, zap.Int("rule_id", it.RuleID), zap.Int("status", interruptionStatus(it)))
	}
	if forced {
		fields = append(fields, zap.Bool("forced", true))
	}
	client, _ := clientIP(r)
	fields = append(fields,
		zap.Ints("rule_ids", ids),
		zap.String("severity", severity),
		zap.String("message", message),
		zap.String("host", r.Host),
		zap.String("method", r.Method),
		zap.String("uri", r.RequestURI),
		zap.String("client_ip", client),
	)
	ce.Write(fields...)
}
