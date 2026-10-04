package decisions

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"syscall"
	"testing"
	"time"
)

type fakeScorer struct {
	t        *testing.T
	listener *net.UnixListener
	path     string
}

func newFakeScorer(t *testing.T) *fakeScorer {
	t.Helper()
	path := filepath.Join(t.TempDir(), "decisions.sock")
	listener, err := net.Listen("unix", path)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	return &fakeScorer{t: t, listener: listener.(*net.UnixListener), path: path}
}

func (f *fakeScorer) accept() net.Conn {
	f.t.Helper()
	conn, err := f.listener.Accept()
	if err != nil {
		f.t.Fatalf("accept: %v", err)
	}
	return conn
}

func (f *fakeScorer) close() {
	f.listener.Close()
}

func writeLine(t *testing.T, conn net.Conn, line string) {
	t.Helper()
	if _, err := conn.Write([]byte(line + "\n")); err != nil {
		t.Fatalf("write: %v", err)
	}
}

func waitUntil(t *testing.T, timeout time.Duration, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("condition not met within %s", timeout)
}

func TestSubscriber_S_decision_feed_enabled_scorer_running(t *testing.T) {
	scorer := newFakeScorer(t)
	defer scorer.close()

	store := NewStore(10)
	sub := NewSubscriber(store)
	sub.Start(SubscriberConfig{SocketPath: scorer.path, ScorerUID: os.Getuid(), MaxEntries: 10}, true)
	defer sub.Stop()

	conn := scorer.accept()
	defer conn.Close()

	writeLine(t, conn, `{"type":"sync_begin"}`)
	writeLine(t, conn, decisionPutLine("203.0.113.5|ja4-a", TierRisky, time.Now().Add(time.Hour)))
	writeLine(t, conn, `{"type":"sync_end"}`)

	waitUntil(t, time.Second, func() bool { return store.Len() == 1 })
}

func TestSubscriber_S_decision_feed_scorer_down_at_startup(t *testing.T) {
	path := filepath.Join(t.TempDir(), "decisions.sock")
	store := NewStore(10)
	sub := NewSubscriber(store)
	sub.Start(SubscriberConfig{SocketPath: path, ScorerUID: os.Getuid(), MaxEntries: 10}, false)
	defer sub.Stop()

	time.Sleep(50 * time.Millisecond)
	if store.Len() != 0 {
		t.Fatalf("Len() = %d, want 0 while the scorer is down", store.Len())
	}

	listener, err := net.Listen("unix", path)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer listener.Close()

	conn, err := listener.Accept()
	if err != nil {
		t.Fatalf("accept: %v", err)
	}
	defer conn.Close()

	writeLine(t, conn, `{"type":"sync_begin"}`)
	writeLine(t, conn, decisionPutLine("203.0.113.5|ja4-a", TierRisky, time.Now().Add(time.Hour)))
	writeLine(t, conn, `{"type":"sync_end"}`)
	waitUntil(t, 2*time.Second, func() bool { return store.Len() == 1 })
}

func TestSubscriber_S_decision_feed_scorer_stopped(t *testing.T) {
	scorer := newFakeScorer(t)
	defer scorer.close()

	store := NewStore(10)
	sub := NewSubscriber(store)
	sub.Start(SubscriberConfig{SocketPath: scorer.path, ScorerUID: os.Getuid(), MaxEntries: 10}, false)
	defer sub.Stop()

	conn := scorer.accept()
	writeLine(t, conn, `{"type":"sync_begin"}`)
	writeLine(t, conn, decisionPutLine("203.0.113.5|ja4-a", TierRisky, time.Now().Add(time.Hour)))
	writeLine(t, conn, `{"type":"sync_end"}`)
	waitUntil(t, time.Second, func() bool { return store.Len() == 1 })

	conn.Close()
	scorer.close()

	time.Sleep(50 * time.Millisecond)
	if _, ok := store.Resolve("203.0.113.5", "ja4-a", time.Now()); !ok {
		t.Fatal("expected the existing decision to keep matching after the scorer stops")
	}
}

func TestSubscriber_S_decision_feed_scorer_restarts(t *testing.T) {
	path := filepath.Join(t.TempDir(), "decisions.sock")
	listener, err := net.Listen("unix", path)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}

	store := NewStore(10)
	sub := NewSubscriber(store)
	sub.Start(SubscriberConfig{SocketPath: path, ScorerUID: os.Getuid(), MaxEntries: 10}, false)
	defer sub.Stop()

	conn, err := listener.Accept()
	if err != nil {
		t.Fatalf("accept: %v", err)
	}
	writeLine(t, conn, `{"type":"sync_begin"}`)
	writeLine(t, conn, decisionPutLine("203.0.113.5|ja4-a", TierRisky, time.Now().Add(time.Hour)))
	writeLine(t, conn, `{"type":"sync_end"}`)
	waitUntil(t, time.Second, func() bool { return store.Len() == 1 })

	conn.Close()
	listener.Close()

	listener2, err := net.Listen("unix", path)
	if err != nil {
		t.Fatalf("relisten: %v", err)
	}
	defer listener2.Close()

	conn2, err := listener2.Accept()
	if err != nil {
		t.Fatalf("accept2: %v", err)
	}
	defer conn2.Close()

	writeLine(t, conn2, `{"type":"sync_begin"}`)
	writeLine(t, conn2, decisionPutLine("198.51.100.9|ja4-b", TierDangerous, time.Now().Add(time.Hour)))
	writeLine(t, conn2, `{"type":"sync_end"}`)

	waitUntil(t, 35*time.Second, func() bool {
		_, ok := store.Resolve("198.51.100.9", "ja4-b", time.Now())
		return ok
	})
	if _, ok := store.Resolve("203.0.113.5", "ja4-a", time.Now()); ok {
		t.Fatal("expected the stale decision to be gone after resync")
	}
}

func TestSubscriber_S_decision_feed_sync_interrupted(t *testing.T) {
	scorer := newFakeScorer(t)
	defer scorer.close()

	store := NewStore(10)
	sub := NewSubscriber(store)
	sub.Start(SubscriberConfig{SocketPath: scorer.path, ScorerUID: os.Getuid(), MaxEntries: 10}, false)
	defer sub.Stop()

	conn := scorer.accept()
	writeLine(t, conn, `{"type":"sync_begin"}`)
	writeLine(t, conn, decisionPutLine("203.0.113.5|ja4-a", TierRisky, time.Now().Add(time.Hour)))
	conn.Close()

	time.Sleep(100 * time.Millisecond)
	if store.Len() != 0 {
		t.Fatalf("Len() = %d, want 0: an interrupted sync must not change the store", store.Len())
	}
}

func TestSubscriber_S_decision_feed_incremental_put(t *testing.T) {
	scorer := newFakeScorer(t)
	defer scorer.close()

	store := NewStore(10)
	sub := NewSubscriber(store)
	sub.Start(SubscriberConfig{SocketPath: scorer.path, ScorerUID: os.Getuid(), MaxEntries: 10}, false)
	defer sub.Stop()

	conn := scorer.accept()
	defer conn.Close()
	writeLine(t, conn, `{"type":"sync_begin"}`)
	writeLine(t, conn, `{"type":"sync_end"}`)
	waitUntil(t, time.Second, func() bool { return true })

	writeLine(t, conn, decisionPutLine("203.0.113.5|ja4-a", TierDangerous, time.Now().Add(time.Hour)))

	waitUntil(t, time.Second, func() bool {
		_, ok := store.Resolve("203.0.113.5", "ja4-a", time.Now())
		return ok
	})
}

func TestSubscriber_InvalidPutsAreSkipped(t *testing.T) {
	scorer := newFakeScorer(t)
	defer scorer.close()

	store := NewStore(10)
	sub := NewSubscriber(store)
	sub.Start(SubscriberConfig{SocketPath: scorer.path, ScorerUID: os.Getuid(), MaxEntries: 10}, false)
	defer sub.Stop()

	conn := scorer.accept()
	defer conn.Close()
	writeLine(t, conn, `{"type":"sync_begin"}`)
	writeLine(t, conn, `{"type":"sync_end"}`)

	later := time.Now().Add(time.Hour)
	writeLine(t, conn, decisionPutLine("203.0.113.6|ja4-b", "suspicious", later))
	writeLine(t, conn, decisionPutLine("no-separator-key", TierRisky, later))
	writeLine(t, conn, `{"type":"put","decision":{"key":"203.0.113.7|ja4-c","tier":"risky","score":0.5,"expires_at":"not-a-time","reason":"test","model_version":"test-1"}}`)
	writeLine(t, conn, decisionPutLine("203.0.113.5|ja4-a", TierDangerous, later))

	waitUntil(t, time.Second, func() bool {
		_, ok := store.Resolve("203.0.113.5", "ja4-a", time.Now())
		return ok
	})
	if store.Len() != 1 {
		t.Fatalf("Len() = %d, want 1: only the valid put may be stored", store.Len())
	}
	if _, ok := store.Resolve("203.0.113.6", "ja4-b", time.Now()); ok {
		t.Fatal("a put with an unknown tier was stored")
	}
	if _, ok := store.Resolve("203.0.113.7", "ja4-c", time.Now()); ok {
		t.Fatal("a put with an unparsable expires_at was stored")
	}
}

func TestSubscriber_MalformedDelIsSkipped(t *testing.T) {
	scorer := newFakeScorer(t)
	defer scorer.close()

	store := NewStore(10)
	sub := NewSubscriber(store)
	sub.Start(SubscriberConfig{SocketPath: scorer.path, ScorerUID: os.Getuid(), MaxEntries: 10}, false)
	defer sub.Stop()

	conn := scorer.accept()
	defer conn.Close()

	later := time.Now().Add(time.Hour)
	badKeys := []string{"no-separator", "", "not-an-ip|ja4-a", "203.0.113.5|", "|ja4-a"}

	writeLine(t, conn, `{"type":"sync_begin"}`)
	writeLine(t, conn, decisionPutLine("203.0.113.5|ja4-a", TierRisky, later))
	for _, key := range badKeys {
		writeLine(t, conn, fmt.Sprintf(`{"type":"del","key":%q}`, key))
	}
	writeLine(t, conn, `{"type":"sync_end"}`)

	for _, key := range badKeys {
		writeLine(t, conn, fmt.Sprintf(`{"type":"del","key":%q}`, key))
	}
	writeLine(t, conn, decisionPutLine("203.0.113.6|ja4-b", TierDangerous, later))

	waitUntil(t, time.Second, func() bool {
		_, ok := store.Resolve("203.0.113.6", "ja4-b", time.Now())
		return ok
	})
	if _, ok := store.Resolve("203.0.113.5", "ja4-a", time.Now()); !ok {
		t.Fatal("the synced decision was lost after malformed del lines")
	}
	if store.Len() != 2 {
		t.Fatalf("Len() = %d, want 2", store.Len())
	}
}

func TestSubscriber_SweepsExpiredDecisionsInTheBackground(t *testing.T) {
	saved := sweepInterval
	sweepInterval = 20 * time.Millisecond
	defer func() { sweepInterval = saved }()

	scorer := newFakeScorer(t)
	defer scorer.close()

	store := NewStore(10)
	sub := NewSubscriber(store)
	sub.Start(SubscriberConfig{SocketPath: scorer.path, ScorerUID: os.Getuid(), MaxEntries: 10}, false)
	defer sub.Stop()

	conn := scorer.accept()
	defer conn.Close()
	writeLine(t, conn, `{"type":"sync_begin"}`)
	writeLine(t, conn, decisionPutLine("203.0.113.5|ja4-a", TierRisky, time.Now().Add(2*time.Second)))
	writeLine(t, conn, decisionPutLine("203.0.113.6|ja4-b", TierRisky, time.Now().Add(time.Hour)))
	writeLine(t, conn, `{"type":"sync_end"}`)
	waitUntil(t, time.Second, func() bool { return store.Len() == 2 })

	waitUntil(t, 5*time.Second, func() bool { return store.Len() == 1 })
	if _, ok := store.Resolve("203.0.113.6", "ja4-b", time.Now()); !ok {
		t.Fatal("the unexpired decision was swept")
	}
}

func TestSubscriber_S_decision_feed_incremental_del(t *testing.T) {
	scorer := newFakeScorer(t)
	defer scorer.close()

	store := NewStore(10)
	sub := NewSubscriber(store)
	sub.Start(SubscriberConfig{SocketPath: scorer.path, ScorerUID: os.Getuid(), MaxEntries: 10}, false)
	defer sub.Stop()

	conn := scorer.accept()
	defer conn.Close()
	writeLine(t, conn, `{"type":"sync_begin"}`)
	writeLine(t, conn, decisionPutLine("203.0.113.5|ja4-a", TierRisky, time.Now().Add(time.Hour)))
	writeLine(t, conn, `{"type":"sync_end"}`)
	waitUntil(t, time.Second, func() bool { return store.Len() == 1 })

	writeLine(t, conn, `{"type":"del","key":"203.0.113.5|ja4-a"}`)

	waitUntil(t, time.Second, func() bool { return store.Len() == 0 })
}

func TestSubscriber_S_decision_feed_malformed_line(t *testing.T) {
	scorer := newFakeScorer(t)
	defer scorer.close()

	store := NewStore(10)
	sub := NewSubscriber(store)
	sub.Start(SubscriberConfig{SocketPath: scorer.path, ScorerUID: os.Getuid(), MaxEntries: 10}, false)
	defer sub.Stop()

	conn := scorer.accept()
	defer conn.Close()
	writeLine(t, conn, `{"type":"sync_begin"}`)
	writeLine(t, conn, `not valid json`)
	writeLine(t, conn, decisionPutLine("203.0.113.5|ja4-a", TierRisky, time.Now().Add(time.Hour)))
	writeLine(t, conn, `{"type":"sync_end"}`)

	waitUntil(t, time.Second, func() bool { return store.Len() == 1 })
}

func TestSubscriber_S_decision_feed_oversized_line(t *testing.T) {
	scorer := newFakeScorer(t)
	defer scorer.close()

	store := NewStore(10)
	sub := NewSubscriber(store)
	sub.Start(SubscriberConfig{SocketPath: scorer.path, ScorerUID: os.Getuid(), MaxEntries: 10}, false)
	defer sub.Stop()

	conn := scorer.accept()
	defer conn.Close()
	writeLine(t, conn, `{"type":"sync_begin"}`)

	huge := make([]byte, maxLineBytes*2)
	for i := range huge {
		huge[i] = 'a'
	}
	writeLine(t, conn, `{"type":"put","decision":{"key":"203.0.113.5|`+string(huge)+`","tier":"risky"}}`)
	writeLine(t, conn, decisionPutLine("203.0.113.5|ja4-a", TierRisky, time.Now().Add(time.Hour)))
	writeLine(t, conn, `{"type":"sync_end"}`)

	waitUntil(t, time.Second, func() bool { return store.Len() == 1 })
}

func TestSubscriber_S_decision_feed_expiry_too_far_ahead(t *testing.T) {
	scorer := newFakeScorer(t)
	defer scorer.close()

	store := NewStore(10)
	sub := NewSubscriber(store)
	sub.Start(SubscriberConfig{SocketPath: scorer.path, ScorerUID: os.Getuid(), MaxEntries: 10}, false)
	defer sub.Stop()

	conn := scorer.accept()
	defer conn.Close()
	writeLine(t, conn, `{"type":"sync_begin"}`)
	writeLine(t, conn, decisionPutLine("203.0.113.5|ja4-a", TierRisky, time.Now().Add(48*time.Hour)))
	writeLine(t, conn, decisionPutLine("198.51.100.9|ja4-b", TierRisky, time.Now().Add(time.Hour)))
	writeLine(t, conn, `{"type":"sync_end"}`)

	waitUntil(t, time.Second, func() bool { return store.Len() == 1 })
	if _, ok := store.Resolve("203.0.113.5", "ja4-a", time.Now()); ok {
		t.Fatal("expected the decision expiring 48h ahead to be skipped")
	}
}

func TestSubscriber_S_decision_feed_unexpected_peer(t *testing.T) {
	scorer := newFakeScorer(t)
	defer scorer.close()

	store := NewStore(10)
	sub := NewSubscriber(store)
	sub.Start(SubscriberConfig{SocketPath: scorer.path, ScorerUID: os.Getuid() + 1, MaxEntries: 10}, false)
	defer sub.Stop()

	conn := scorer.accept()
	defer conn.Close()

	sync := `{"type":"sync_begin"}` + "\n" +
		decisionPutLine("203.0.113.9|ja4-x", TierDangerous, time.Now().Add(time.Hour)) + "\n" +
		`{"type":"sync_end"}` + "\n"
	_, _ = conn.Write([]byte(sync))

	if err := conn.SetReadDeadline(time.Now().Add(2 * time.Second)); err != nil {
		t.Fatalf("set read deadline: %v", err)
	}
	buf := make([]byte, 64)
	if _, err := conn.Read(buf); !errors.Is(err, io.EOF) && !errors.Is(err, syscall.ECONNRESET) {
		t.Fatalf("read from refused connection: err = %v, want EOF or reset because the subscriber must close it", err)
	}

	time.Sleep(100 * time.Millisecond)
	if store.Len() != 0 {
		t.Fatalf("Len() = %d, want 0: a sync from an unexpected uid must be ignored", store.Len())
	}
}

func TestSubscriber_S_decision_feed_kill_switch(t *testing.T) {
	scorer := newFakeScorer(t)
	defer scorer.close()

	store := NewStore(10)
	sub := NewSubscriber(store)
	sub.Start(SubscriberConfig{SocketPath: scorer.path, ScorerUID: os.Getuid(), MaxEntries: 10}, false)

	conn := scorer.accept()
	writeLine(t, conn, `{"type":"sync_begin"}`)
	writeLine(t, conn, decisionPutLine("203.0.113.5|ja4-a", TierRisky, time.Now().Add(time.Hour)))
	writeLine(t, conn, `{"type":"sync_end"}`)
	waitUntil(t, time.Second, func() bool { return store.Len() == 1 })

	sub.Stop()
	conn.Close()

	if store.Len() != 0 {
		t.Fatalf("Len() = %d, want 0 after the kill switch stops the subscriber", store.Len())
	}
}

func TestSubscriber_S_decision_feed_large_sync(t *testing.T) {
	scorer := newFakeScorer(t)
	defer scorer.close()

	store := NewStore(100_000)
	sub := NewSubscriber(store)
	sub.Start(SubscriberConfig{SocketPath: scorer.path, ScorerUID: os.Getuid(), MaxEntries: 100_000}, false)
	defer sub.Stop()

	conn := scorer.accept()
	defer conn.Close()

	writer := bufio.NewWriter(conn)
	fmt.Fprintln(writer, `{"type":"sync_begin"}`)
	for i := 0; i < 50_000; i++ {
		key := decisionKeyForIndex(i)
		fmt.Fprintln(writer, decisionPutLine(key, TierRisky, time.Now().Add(time.Hour)))
	}
	fmt.Fprintln(writer, `{"type":"sync_end"}`)
	if err := writer.Flush(); err != nil {
		t.Fatalf("flush: %v", err)
	}

	waitUntil(t, 10*time.Second, func() bool { return store.Len() == 50_000 })
}

func TestSubscriber_S_verification_no_request_waits_5ms_during_100000_sync(t *testing.T) {
	scorer := newFakeScorer(t)
	defer scorer.close()

	store := NewStore(100_000)
	sub := NewSubscriber(store)
	sub.Start(SubscriberConfig{SocketPath: scorer.path, ScorerUID: os.Getuid(), MaxEntries: 100_000}, false)
	defer sub.Stop()

	conn := scorer.accept()
	defer conn.Close()

	stopResolving := make(chan struct{})
	maxWait := make(chan time.Duration, 1)
	go func() {
		var worst time.Duration
		now := time.Now()
		for {
			select {
			case <-stopResolving:
				maxWait <- worst
				return
			default:
			}
			start := time.Now()
			store.Resolve("203.0.113.5", "ja4-a", now)
			if d := time.Since(start); d > worst {
				worst = d
			}
			runtime.Gosched()
		}
	}()

	writer := bufio.NewWriter(conn)
	fmt.Fprintln(writer, `{"type":"sync_begin"}`)
	for i := 0; i < 100_000; i++ {
		key := decisionKeyForIndex(i)
		fmt.Fprintln(writer, decisionPutLine(key, TierRisky, time.Now().Add(time.Hour)))
	}
	fmt.Fprintln(writer, `{"type":"sync_end"}`)
	if err := writer.Flush(); err != nil {
		t.Fatalf("flush: %v", err)
	}

	waitUntil(t, 10*time.Second, func() bool { return store.Len() == 100_000 })
	close(stopResolving)
	worst := <-maxWait
	t.Logf("worst concurrent Resolve() wait during the 100,000-decision sync: %s", worst)

	if worst > 5*time.Millisecond {
		t.Fatalf("a concurrent Resolve() call waited %s during the 100,000-decision sync, want <= 5ms", worst)
	}
}

func decisionPutLine(key, tier string, expiresAt time.Time) string {
	return fmt.Sprintf(
		`{"type":"put","decision":{"key":%q,"tier":%q,"score":0.5,"expires_at":%q,"reason":"test","model_version":"test-1"}}`,
		key, tier, expiresAt.UTC().Format(time.RFC3339),
	)
}
