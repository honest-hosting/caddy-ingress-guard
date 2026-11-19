// Command ingress-guard-bundle creates keys, keysets and signed bundles with local Ed25519 keys,
// and pushes them to a module's loopback endpoint. It is the S2 spike's agent stub and the
// open-source development flow; production signing uses Vault Transit in the security service.
//
//	ingress-guard-bundle keygen  -dir keys -name root
//	ingress-guard-bundle keyset  -root keys/root.key -root-id root -signer signer-1=keys/signer-1.pub -out keyset.pb
//	ingress-guard-bundle build   -keyset keyset.pb -signer keys/signer-1.key -signer-id signer-1 \
//	                             -target site:<uuid> -pre rules.conf -out bundle.pb
//	ingress-guard-bundle inspect bundle.pb
//	ingress-guard-bundle push    -url http://127.0.0.1:2020/v1/bundle bundle.pb
//	ingress-guard-bundle flip    -keyset keyset.pb -signer ... -target site:<uuid> -a a.conf -b b.conf -every 2s
//	ingress-guard-bundle junk    -url http://127.0.0.1:2020/v1/bundle -rate 50 -workers 1 -duration 60s
//	ingress-guard-bundle ingress -keyset keyset.pb -signer ... -target ingress:<pool> -crs-dir ... \
//	                             -sites 5000 -seed 1 [-single] [-count 60 -every 10s] -out ingress.pb
package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/csv"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"

	"github.com/honest-hosting/caddy-ingress-guard/bundle"
	"github.com/honest-hosting/caddy-ingress-guard/bundle/bundlepb"
)

func main() {
	if len(os.Args) < 2 {
		usage()
	}
	cmds := map[string]func([]string) error{
		"keygen": keygen, "keyset": keyset, "build": build, "inspect": inspect,
		"push": push, "flip": flip, "junk": junk, "ingress": ingress,
	}
	fn, ok := cmds[os.Args[1]]
	if !ok {
		usage()
	}
	if err := fn(os.Args[2:]); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

func usage() {
	fmt.Fprintln(os.Stderr, "usage: ingress-guard-bundle keygen|keyset|build|inspect|push|flip|junk|ingress [flags]")
	os.Exit(2)
}

// ---- keys ----

func keygen(args []string) error {
	fl := flag.NewFlagSet("keygen", flag.ExitOnError)
	dir := fl.String("dir", ".", "output directory")
	name := fl.String("name", "", "key name, e.g. root or signer-1")
	_ = fl.Parse(args)
	if *name == "" {
		return errors.New("-name is required")
	}
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(*dir, 0o700); err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(*dir, *name+".key"), []byte(base64.StdEncoding.EncodeToString(priv.Seed())+"\n"), 0o600); err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(*dir, *name+".pub"), []byte(base64.StdEncoding.EncodeToString(pub)+"\n"), 0o644); err != nil {
		return err
	}
	fmt.Printf("%s public key (root_key value): %s\n", *name, base64.StdEncoding.EncodeToString(pub))
	return nil
}

func readKey(path string) (ed25519.PrivateKey, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	seed, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(b)))
	if err != nil || len(seed) != ed25519.SeedSize {
		return nil, fmt.Errorf("%s: not a base64 Ed25519 seed", path)
	}
	return ed25519.NewKeyFromSeed(seed), nil
}

func readPub(path string) (ed25519.PublicKey, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	k, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(b)))
	if err != nil || len(k) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("%s: not a base64 Ed25519 public key", path)
	}
	return ed25519.PublicKey(k), nil
}

type multiFlag []string

func (m *multiFlag) String() string     { return strings.Join(*m, ",") }
func (m *multiFlag) Set(v string) error { *m = append(*m, v); return nil }

func keyset(args []string) error {
	fl := flag.NewFlagSet("keyset", flag.ExitOnError)
	rootPath := fl.String("root", "", "root private key file")
	rootID := fl.String("root-id", "root", "root key ID (matches the module's root_key ID)")
	version := fl.Uint64("version", 1, "keyset version")
	validity := fl.Duration("validity", 365*24*time.Hour, "signer validity from now")
	out := fl.String("out", "keyset.pb", "output file")
	var signers multiFlag
	fl.Var(&signers, "signer", "signer key: <key_id>=<public key file> (repeatable)")
	_ = fl.Parse(args)
	root, err := readKey(*rootPath)
	if err != nil {
		return err
	}
	now := time.Now()
	ks := &bundlepb.Keyset{FormatVersion: bundle.FormatVersion, KeysetVersion: *version, IssuedAt: now.Unix()}
	for _, s := range signers {
		id, path, ok := strings.Cut(s, "=")
		if !ok {
			return fmt.Errorf("-signer %q: want <key_id>=<file>", s)
		}
		pub, err := readPub(path)
		if err != nil {
			return err
		}
		ks.Keys = append(ks.Keys, &bundlepb.SignerKey{
			KeyId: id, Ed25519PublicKey: pub,
			NotBefore: now.Add(-time.Hour).Unix(), NotAfter: now.Add(*validity).Unix(),
		})
	}
	sks, err := bundle.SignKeyset(ks, bundle.Ed25519Signer{ID: *rootID, Key: root})
	if err != nil {
		return err
	}
	b, err := proto.Marshal(sks)
	if err != nil {
		return err
	}
	return os.WriteFile(*out, b, 0o644)
}

// ---- build ----

type buildFlags struct {
	keyset, signerKey, signerID, target, mode, crsDir, crsVersion string
	pre, crsSetup, post                                           string
	ttl                                                           time.Duration
	seq                                                           uint64
	requires                                                      multiFlag
}

func (b *buildFlags) register(fl *flag.FlagSet) {
	fl.StringVar(&b.keyset, "keyset", "keyset.pb", "signed keyset file")
	fl.StringVar(&b.signerKey, "signer", "", "signer private key file")
	fl.StringVar(&b.signerID, "signer-id", "signer-1", "signer key ID in the keyset")
	fl.StringVar(&b.target, "target", "", "target, e.g. site:<uuid>, layer:global")
	fl.StringVar(&b.mode, "mode", "enforce", "switches mode: enforce|detect|off|none (no switches section)")
	fl.StringVar(&b.pre, "pre", "", "SecLang file for the coraza pre slot")
	fl.StringVar(&b.crsSetup, "crs-setup", "", "SecLang file for the coraza crs_setup slot")
	fl.StringVar(&b.post, "post", "", "SecLang file for the coraza post slot")
	fl.StringVar(&b.crsDir, "crs-dir", "", "CRS directory (rules/, plugins/) to carry as bundle data")
	fl.StringVar(&b.crsVersion, "crs-version", "", "CRS version recorded in the manifest")
	fl.DurationVar(&b.ttl, "ttl", 14*24*time.Hour, "expiry from now (A1: 14 days)")
	fl.Uint64Var(&b.seq, "seq", 0, "sequence (0: time-based)")
	fl.Var(&b.requires, "require", "layer constraint <target>=<min sequence> (repeatable)")
}

type builder struct {
	f      buildFlags
	keyset *bundlepb.SignedKeyset
	signer bundle.Signer
	crs    map[string][]byte
	last   uint64
	// extraPre is appended to the pre slot (flip -unique).
	extraPre string
	// extra sections are added as they are (ingress: profiles).
	extra []bundle.SectionInput
}

func newBuilder(f buildFlags) (*builder, error) {
	b := &builder{f: f}
	raw, err := os.ReadFile(f.keyset)
	if err != nil {
		return nil, err
	}
	b.keyset = &bundlepb.SignedKeyset{}
	if err := proto.Unmarshal(raw, b.keyset); err != nil {
		return nil, fmt.Errorf("keyset: %w", err)
	}
	key, err := readKey(f.signerKey)
	if err != nil {
		return nil, err
	}
	b.signer = bundle.Ed25519Signer{ID: f.signerID, Key: key}
	if f.crsDir != "" {
		b.crs = map[string][]byte{}
		err := filepath.WalkDir(f.crsDir, func(p string, d fs.DirEntry, err error) error {
			if err != nil || d.IsDir() {
				return err
			}
			if !strings.HasSuffix(p, ".conf") && !strings.HasSuffix(p, ".data") {
				return nil
			}
			rel, _ := filepath.Rel(f.crsDir, p)
			data, err := os.ReadFile(p)
			b.crs[filepath.ToSlash(rel)] = data
			return err
		})
		if err != nil {
			return nil, err
		}
	}
	return b, nil
}

func readOpt(path string) (string, error) {
	if path == "" {
		return "", nil
	}
	b, err := os.ReadFile(path)
	return string(b), err
}

// build creates one bundle; preOverride replaces the pre slot file (flip uses it).
func (b *builder) build(preOverride string) ([]byte, *bundlepb.Manifest, error) {
	prePath := b.f.pre
	if preOverride != "" {
		prePath = preOverride
	}
	pre, err := readOpt(prePath)
	if err != nil {
		return nil, nil, err
	}
	if b.extraPre != "" {
		pre += "\n" + b.extraPre + "\n"
	}
	setup, err := readOpt(b.f.crsSetup)
	if err != nil {
		return nil, nil, err
	}
	post, err := readOpt(b.f.post)
	if err != nil {
		return nil, nil, err
	}
	var sections []bundle.SectionInput
	if pre != "" || setup != "" || post != "" {
		sections = append(sections, bundle.SectionInput{Name: bundle.SectionCoraza, Required: true,
			Body: &bundlepb.CorazaSection{Pre: pre, CrsSetup: setup, Post: post}})
	}
	if b.crs != nil {
		sections = append(sections, bundle.SectionInput{Name: bundle.SectionCRS, Required: true,
			Body: &bundlepb.CrsSection{Source: &bundlepb.CrsSection_Files{Files: &bundlepb.CrsFiles{Files: b.crs}}}})
	}
	if b.f.mode != "none" {
		modes := map[string]bundlepb.Mode{"enforce": bundlepb.Mode_MODE_ENFORCE, "detect": bundlepb.Mode_MODE_DETECT, "off": bundlepb.Mode_MODE_OFF}
		m, ok := modes[b.f.mode]
		if !ok {
			return nil, nil, fmt.Errorf("-mode %q", b.f.mode)
		}
		sections = append(sections, bundle.SectionInput{Name: bundle.SectionSwitches, Required: true,
			Body: &bundlepb.SwitchesSection{Mode: m}})
	}
	sections = append(sections, b.extra...)
	var constraints []*bundlepb.LayerConstraint
	for _, r := range b.f.requires {
		t, s, ok := strings.Cut(r, "=")
		var min uint64
		if _, err := fmt.Sscan(s, &min); !ok || err != nil {
			return nil, nil, fmt.Errorf("-require %q: want <target>=<sequence>", r)
		}
		constraints = append(constraints, &bundlepb.LayerConstraint{Target: t, MinSequence: min})
	}
	seq := b.f.seq
	if seq == 0 {
		seq = bundle.NextSequence(b.last, time.Now())
	}
	b.last = seq
	now := time.Now()
	sb, err := bundle.Build(bundle.BuildOptions{
		Target: b.f.target, Sequence: seq, IssuedAt: now, ExpiresAt: now.Add(b.f.ttl),
		Sections: sections, LayerConstraints: constraints, CRSVersion: b.f.crsVersion,
		Keyset: b.keyset, Signer: b.signer,
	})
	if err != nil {
		return nil, nil, err
	}
	raw, err := bundle.Marshal(sb)
	if err != nil {
		return nil, nil, err
	}
	m := &bundlepb.Manifest{}
	_ = proto.Unmarshal(sb.GetManifest(), m)
	return raw, m, nil
}

func build(args []string) error {
	fl := flag.NewFlagSet("build", flag.ExitOnError)
	var bf buildFlags
	bf.register(fl)
	out := fl.String("out", "bundle.pb", "output file")
	_ = fl.Parse(args)
	b, err := newBuilder(bf)
	if err != nil {
		return err
	}
	raw, m, err := b.build("")
	if err != nil {
		return err
	}
	fmt.Printf("%s: target=%s sequence=%d bytes=%d (payload decompressed %d)\n",
		*out, m.GetTarget(), m.GetSequence(), len(raw), m.GetPayloadSize())
	return os.WriteFile(*out, raw, 0o644)
}

func inspect(args []string) error {
	if len(args) != 1 {
		return errors.New("usage: inspect <bundle.pb>")
	}
	raw, err := os.ReadFile(args[0])
	if err != nil {
		return err
	}
	p, err := bundle.Peek(raw)
	if err != nil {
		return err
	}
	ks := &bundlepb.Keyset{}
	_ = proto.Unmarshal(p.Signed.GetKeyset().GetKeyset(), ks)
	j := protojson.MarshalOptions{Multiline: true}
	fmt.Printf("bytes: %d (manifest %d, payload %d)\nkey_id: %s\nmanifest: %s\nkeyset: %s\n",
		len(raw), len(p.Signed.GetManifest()), len(p.Signed.GetPayload()), p.Signed.GetKeyId(),
		j.Format(p.Manifest), j.Format(ks))
	return nil
}

// ---- push ----

// client keeps a connection per junk worker alive (the default keeps only 2 idle per host).
var client = func() *http.Client {
	t := http.DefaultTransport.(*http.Transport).Clone()
	t.MaxIdleConnsPerHost = 64
	return &http.Client{Timeout: 60 * time.Second, Transport: t}
}()

func pushRaw(url string, raw []byte) (int, *bundlepb.Ack, time.Duration, error) {
	req, err := http.NewRequest(http.MethodPut, url, bytes.NewReader(raw))
	if err != nil {
		return 0, nil, 0, err
	}
	req.Header.Set("Content-Type", "application/x-protobuf")
	start := time.Now()
	resp, err := client.Do(req)
	if err != nil {
		return 0, nil, time.Since(start), err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	d := time.Since(start)
	ack := &bundlepb.Ack{}
	if resp.Header.Get("Content-Type") == "application/x-protobuf" {
		_ = proto.Unmarshal(body, ack)
	} else {
		ack.Reason = strings.TrimSpace(string(body))
	}
	return resp.StatusCode, ack, d, nil
}

func push(args []string) error {
	fl := flag.NewFlagSet("push", flag.ExitOnError)
	url := fl.String("url", "http://127.0.0.1:2020/v1/bundle", "push endpoint")
	_ = fl.Parse(args)
	if fl.NArg() != 1 {
		return errors.New("usage: push [-url URL] <bundle.pb>")
	}
	raw, err := os.ReadFile(fl.Arg(0))
	if err != nil {
		return err
	}
	status, ack, d, err := pushRaw(*url, raw)
	if err != nil {
		return err
	}
	fmt.Printf("HTTP %d in %s\n%s\n", status, d, protojson.MarshalOptions{Multiline: true}.Format(ack))
	return nil
}

// flip is the S2 agent stub: every interval it builds a fresh bundle alternating between the
// -a and -b pre-slot files (new sequence each time), pushes it, and writes one CSV row per push.
func flip(args []string) error {
	fl := flag.NewFlagSet("flip", flag.ExitOnError)
	var bf buildFlags
	bf.register(fl)
	url := fl.String("url", "http://127.0.0.1:2020/v1/bundle", "push endpoint")
	a := fl.String("a", "", "pre-slot SecLang for bundle A")
	bb := fl.String("b", "", "pre-slot SecLang for bundle B")
	every := fl.Duration("every", 2*time.Second, "push interval")
	count := fl.Int("count", 0, "number of pushes (0: until interrupted)")
	unique := fl.Bool("unique", false, "add a regex no earlier push used, so Coraza's pattern cache sees a new entry every swap")
	_ = fl.Parse(args)
	if *a == "" || *bb == "" {
		return errors.New("-a and -b are required")
	}
	b, err := newBuilder(bf)
	if err != nil {
		return err
	}
	run := time.Now().UnixNano() // patterns stay unique across flip runs against one Caddy
	return pushLoop(*url, *every, *count, func(i int) (string, []byte, *bundlepb.Manifest, error) {
		variant, file := "a", *a
		if i%2 == 1 {
			variant, file = "b", *bb
		}
		if *unique {
			b.extraPre = fmt.Sprintf(`SecRule REQUEST_URI "@rx ^/__hh_unique_%d_%d/[a-z]+$" "id:9100,phase:1,pass,nolog"`, run, i)
		}
		raw, m, err := b.build(file)
		return variant, raw, m, err
	})
}

// pushLoop builds and pushes a bundle every interval (count 0: until interrupted), writing one
// CSV row per push to stdout. vm.sh's summary reads these columns.
func pushLoop(url string, every time.Duration, count int, next func(i int) (variant string, raw []byte, m *bundlepb.Manifest, err error)) error {
	w := csv.NewWriter(os.Stdout)
	_ = w.Write([]string{"time", "variant", "sequence", "bytes", "http_status", "accepted", "reason", "activation_ms", "round_trip_ms"})
	w.Flush()
	t := time.NewTicker(every)
	defer t.Stop()
	for i := 0; count == 0 || i < count; i++ {
		variant, raw, m, err := next(i)
		if err != nil {
			return err
		}
		status, ack, d, err := pushRaw(url, raw)
		reason := ack.GetReason()
		if err != nil {
			reason = err.Error()
		}
		_ = w.Write([]string{time.Now().UTC().Format(time.RFC3339Nano), variant, fmt.Sprint(m.GetSequence()),
			fmt.Sprint(len(raw)), fmt.Sprint(status), fmt.Sprint(ack.GetAccepted()), reason,
			fmt.Sprint(ack.GetActivationMs()), fmt.Sprint(d.Milliseconds())})
		w.Flush()
		<-t.C
	}
	return nil
}

// junk floods the push endpoint the way tenant PHP could: garbage, oversized-looking and
// replayed bodies. It reports status counts; the endpoint must stay cheap and serving must not
// degrade (S2's junk-push row).
func junk(args []string) error {
	fl := flag.NewFlagSet("junk", flag.ExitOnError)
	url := fl.String("url", "http://127.0.0.1:2020/v1/bundle", "push endpoint")
	rate := fl.Int("rate", 50, "requests per second, in total")
	workers := fl.Int("workers", 1, "requests in flight at once; more than the module's slots makes real pushes queue")
	duration := fl.Duration("duration", 60*time.Second, "how long")
	replay := fl.String("replay", "", "optional valid bundle file to replay (old sequence once active)")
	_ = fl.Parse(args)
	var replayRaw []byte
	if *replay != "" {
		var err error
		if replayRaw, err = os.ReadFile(*replay); err != nil {
			return err
		}
	}
	var (
		mu     sync.Mutex
		counts = map[int]int{}
		errs   int
		n      atomic.Int64
		wg     sync.WaitGroup
	)
	from := time.Now()
	deadline := from.Add(*duration)
	tick := time.NewTicker(time.Second / time.Duration(max(*rate, 1)))
	defer tick.Stop()
	for range max(*workers, 1) {
		wg.Go(func() {
			for time.Now().Before(deadline) {
				<-tick.C
				body := replayRaw
				if replayRaw == nil || n.Add(1)%2 == 0 {
					body = make([]byte, 512)
					_, _ = rand.Read(body)
				}
				status, _, _, err := pushRaw(*url, body)
				mu.Lock()
				if err != nil {
					errs++
				} else {
					counts[status]++
				}
				mu.Unlock()
			}
		})
	}
	wg.Wait()
	// The window lets vm.sh's flood_report split flip's pushes into during and outside the flood.
	fmt.Printf("status counts: %v, transport errors: %d, from %s to %s\n", counts, errs,
		from.UTC().Format(time.RFC3339), time.Now().UTC().Format(time.RFC3339))
	return nil
}
