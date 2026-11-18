package ingressguard

import (
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"
)

// More requests than slots: the extra ones wait for a slot and are then served, never 429 (S2
// run 4), and no more than pushConcurrency run at once.
func TestAdmitQueuesInsteadOfRejecting(t *testing.T) {
	rt := newRuntime()
	release := make(chan struct{})
	var inFlight, peak atomic.Int32
	h := rt.admit(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := inFlight.Add(1)
		for p := peak.Load(); n > p && !peak.CompareAndSwap(p, n); p = peak.Load() {
		}
		<-release
		inFlight.Add(-1)
	}))

	const reqs = 3 * pushConcurrency
	codes := make(chan int, reqs)
	for range reqs {
		go func() {
			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, httptest.NewRequest(http.MethodPut, "/v1/bundle", nil))
			codes <- rec.Code
		}()
	}

	deadline := time.Now().Add(5 * time.Second)
	for inFlight.Load() < pushConcurrency {
		if time.Now().After(deadline) {
			t.Fatal("slots never filled")
		}
		time.Sleep(time.Millisecond)
	}
	time.Sleep(20 * time.Millisecond) // the rest are now waiting for a slot
	if got := inFlight.Load(); got != pushConcurrency {
		t.Fatalf("in flight = %d, want %d", got, pushConcurrency)
	}
	close(release)

	for range reqs {
		if code := <-codes; code != http.StatusOK {
			t.Fatalf("status %d, want 200 (queued, not rejected)", code)
		}
	}
	if p := peak.Load(); p > pushConcurrency {
		t.Fatalf("peak in flight = %d, want <= %d", p, pushConcurrency)
	}
}
