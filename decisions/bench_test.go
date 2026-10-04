package decisions

import (
	"fmt"
	"os"
	"runtime"
	"testing"
	"time"
)

func BenchmarkStore_Resolve_100000Entries_50PercentHits(b *testing.B) {
	const total = 100_000
	store := NewStore(total)
	now := time.Now()
	for i := 0; i < total; i++ {
		key := decisionKeyForIndex(i)
		store.Put(mustDecision(key, TierRisky, 0.2, now.Add(time.Hour)))
	}

	ips := make([]string, total)
	ja4s := make([]string, total)
	for i := 0; i < total; i++ {
		ip, ja4 := ipAndJA4ForIndex(i)
		ips[i] = ip
		ja4s[i] = ja4
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		idx := i % total
		if idx%2 == 0 {
			store.Resolve(ips[idx], ja4s[idx], now)
		} else {
			store.Resolve(ips[idx], "ja4-miss", now)
		}
	}
}

func BenchmarkStore_ReplaceAll_100000(b *testing.B) {
	const total = 100_000
	store := NewStore(total)
	now := time.Now()
	decisions := make(map[string]Decision, total)
	for i := 0; i < total; i++ {
		key := decisionKeyForIndex(i)
		decisions[key] = mustDecision(key, TierRisky, 0.2, now.Add(time.Hour))
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		store.ReplaceAll(decisions)
	}
}

func BenchmarkStore_PutStream_1000PerSecond(b *testing.B) {
	store := NewStore(100_000)
	now := time.Now()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		key := decisionKeyForIndex(i % 200_000)
		store.Put(mustDecision(key, TierRisky, 0.2, now.Add(time.Hour)))
	}
}

func TestStore_RSS_100000Entries(t *testing.T) {
	if os.Getenv("FLOWGUARD_RSS_TEST") == "" {
		t.Skip("set FLOWGUARD_RSS_TEST=1 to run the RSS measurement (needs an isolated process)")
	}

	baseline := currentRSS(t)

	const total = 100_000
	store := NewStore(total)
	now := time.Now()
	for i := 0; i < total; i++ {
		key := decisionKeyForIndex(i)
		store.Put(mustDecision(key, TierRisky, 0.2, now.Add(time.Hour)))
	}
	runtime.KeepAlive(store)

	after := currentRSS(t)
	grew := after - baseline
	const limit = 64 * 1024 * 1024
	t.Logf("RSS before=%d after=%d grew=%d bytes (limit %d)", baseline, after, grew, limit)
	if grew > limit {
		t.Fatalf("resident memory grew by %d bytes, want at most %d", grew, limit)
	}
}

func currentRSS(t *testing.T) int64 {
	t.Helper()
	runtime.GC()
	data, err := os.ReadFile(fmt.Sprintf("/proc/%d/statm", os.Getpid()))
	if err != nil {
		t.Skipf("RSS measurement requires /proc: %v", err)
	}
	var pages, rssPages int64
	if _, err := fmt.Sscanf(string(data), "%d %d", &pages, &rssPages); err != nil {
		t.Fatalf("parse statm: %v", err)
	}
	return rssPages * int64(os.Getpagesize())
}

func ipAndJA4ForIndex(i int) (string, string) {
	return splitKey(decisionKeyForIndex(i))
}
