package decisions

import (
	"net"
	"strconv"
	"testing"
	"time"
)

func mustDecision(key, tier string, score float64, expiresAt time.Time) Decision {
	return Decision{Key: key, Tier: tier, Score: score, ExpiresAt: expiresAt, Reason: "test", ModelVersion: "test-1"}
}

func TestStore_S_decision_rules_exact_tls_match(t *testing.T) {
	store := NewStore(10)
	now := time.Now()
	store.Put(mustDecision("203.0.113.5|ja4-a", TierRisky, 0.1, now.Add(time.Hour)))

	d, ok := store.Resolve("203.0.113.5", "ja4-a", now)
	if !ok || d.Tier != TierRisky {
		t.Fatalf("Resolve = %#v, %v, want risky match", d, ok)
	}
}

func TestStore_S_decision_rules_other_tls_client_unaffected(t *testing.T) {
	store := NewStore(10)
	now := time.Now()
	store.Put(mustDecision("203.0.113.5|ja4-a", TierDangerous, 0.9, now.Add(time.Hour)))
	store.Put(mustDecision("203.0.113.5|*", TierDangerous, 0.9, now.Add(time.Hour)))

	_, ok := store.Resolve("203.0.113.5", "ja4-b", now)
	if ok {
		t.Fatal("expected no decision for a different JA4 on the same IP")
	}
}

func TestStore_S_decision_rules_dangerous_switches_plain_http(t *testing.T) {
	store := NewStore(10)
	now := time.Now()
	store.Put(mustDecision("203.0.113.5|*", TierDangerous, 0.9, now.Add(time.Hour)))

	d, ok := store.Resolve("203.0.113.5", "", now)
	if !ok || d.Tier != TierDangerous {
		t.Fatalf("Resolve = %#v, %v, want dangerous via aggregate", d, ok)
	}
}

func TestStore_S_decision_rules_plain_http_and_aggregate(t *testing.T) {
	store := NewStore(10)
	now := time.Now()
	store.Put(mustDecision("203.0.113.5|-", TierRisky, 0.2, now.Add(time.Hour)))
	store.Put(mustDecision("203.0.113.5|*", TierDangerous, 0.9, now.Add(time.Hour)))

	d, ok := store.Resolve("203.0.113.5", "", now)
	if !ok || d.Tier != TierDangerous {
		t.Fatalf("Resolve = %#v, %v, want dangerous (highest tier)", d, ok)
	}
}

func TestStore_S_decision_rules_risky_tls_not_plain_http(t *testing.T) {
	store := NewStore(10)
	now := time.Now()
	store.Put(mustDecision("203.0.113.5|ja4-a", TierRisky, 0.2, now.Add(time.Hour)))

	_, ok := store.Resolve("203.0.113.5", "", now)
	if ok {
		t.Fatal("expected a risky-only TLS decision not to cover plain HTTP")
	}
}

func TestStore_S_decision_rules_plain_http_not_tls(t *testing.T) {
	store := NewStore(10)
	now := time.Now()
	store.Put(mustDecision("203.0.113.5|-", TierDangerous, 0.9, now.Add(time.Hour)))

	_, ok := store.Resolve("203.0.113.5", "ja4-a", now)
	if ok {
		t.Fatal("expected the plain-HTTP verdict not to cover a TLS request")
	}
}

func TestStore_S_decision_rules_large_store_memory_only(t *testing.T) {
	store := NewStore(100_000)
	now := time.Now()
	for i := 0; i < 100_000; i++ {
		key := decisionKeyForIndex(i)
		store.Put(mustDecision(key, TierRisky, 0.2, now.Add(time.Hour)))
	}
	if store.Len() != 100_000 {
		t.Fatalf("Len() = %d, want 100000", store.Len())
	}

	d, ok := store.Resolve("10.0.0.1", "ja4-1", now)
	if !ok || d.Tier != TierRisky {
		t.Fatalf("Resolve under a full store = %#v, %v, want a hit", d, ok)
	}
	if _, ok := store.Resolve("10.0.0.1", "ja4-missing", now); ok {
		t.Fatal("expected a miss for an unknown key")
	}
}

func TestStore_S_decision_feed_expiry_scorer_stalls(t *testing.T) {
	store := NewStore(10)
	now := time.Now()
	store.Put(mustDecision("203.0.113.5|ja4-a", TierRisky, 0.2, now.Add(time.Second)))

	if _, ok := store.Resolve("203.0.113.5", "ja4-a", now); !ok {
		t.Fatal("expected the decision to match before it expires")
	}
	past := now.Add(2 * time.Second)
	if _, ok := store.Resolve("203.0.113.5", "ja4-a", past); ok {
		t.Fatal("expected the decision to stop matching once expired, with no removal message")
	}
}

func TestStore_S_decision_feed_cap_reached(t *testing.T) {
	store := NewStore(2)
	now := time.Now()
	store.Put(mustDecision("1.1.1.1|a", TierRisky, 0.1, now.Add(10*time.Minute)))
	store.Put(mustDecision("2.2.2.2|a", TierRisky, 0.1, now.Add(5*time.Minute)))
	if store.Len() != 2 {
		t.Fatalf("Len() = %d, want 2", store.Len())
	}

	store.Put(mustDecision("3.3.3.3|a", TierRisky, 0.1, now.Add(20*time.Minute)))
	if store.Len() != 2 {
		t.Fatalf("Len() after cap = %d, want 2", store.Len())
	}
	if _, ok := store.Resolve("2.2.2.2", "a", now); ok {
		t.Fatal("expected the entry closest to expiry to be dropped first")
	}
	if _, ok := store.Resolve("1.1.1.1", "a", now); !ok {
		t.Fatal("expected the later-expiring entry to survive the cap")
	}
	if _, ok := store.Resolve("3.3.3.3", "a", now); !ok {
		t.Fatal("expected the newly inserted entry to survive the cap")
	}
}

func TestStore_S_decision_feed_stale_removed_by_sync(t *testing.T) {
	store := NewStore(10)
	now := time.Now()
	store.Put(mustDecision("1.1.1.1|a", TierRisky, 0.1, now.Add(time.Hour)))

	store.ReplaceAll(map[string]Decision{
		"2.2.2.2|a": mustDecision("2.2.2.2|a", TierRisky, 0.1, now.Add(time.Hour)),
	})

	if _, ok := store.Resolve("1.1.1.1", "a", now); ok {
		t.Fatal("expected a decision absent from a completed sync to stop matching")
	}
	if _, ok := store.Resolve("2.2.2.2", "a", now); !ok {
		t.Fatal("expected the synced decision to match")
	}
}

func TestStore_S_decision_feed_large_sync(t *testing.T) {
	store := NewStore(100_000)
	now := time.Now()
	decisions := make(map[string]Decision, 50_000)
	for i := 0; i < 50_000; i++ {
		key := decisionKeyForIndex(i)
		decisions[key] = mustDecision(key, TierRisky, 0.2, now.Add(time.Hour))
	}

	store.ReplaceAll(decisions)

	if store.Len() != 50_000 {
		t.Fatalf("Len() = %d, want 50000", store.Len())
	}
	if _, ok := store.Resolve("10.0.0.1", "ja4-1", now); !ok {
		t.Fatal("expected a decision from the large sync to be applied")
	}
}

func TestStore_S_verification_put_after_large_sync_does_not_corrupt_heap(t *testing.T) {
	store := NewStore(100_000)
	now := time.Now()
	decisions := make(map[string]Decision, 100_000)
	for i := 0; i < 100_000; i++ {
		key := decisionKeyForIndex(i)
		decisions[key] = mustDecision(key, TierRisky, 0.2, now.Add(time.Duration(i+1)*time.Second))
	}

	store.ReplaceAll(decisions)

	for i, entry := range store.heap {
		if entry.index != i {
			t.Fatalf("heap entry at position %d has stale index %d after ReplaceAll", i, entry.index)
		}
	}

	for i := 0; i < 2000; i++ {
		ip, ja4 := ipAndJA4ForIndex(100_000 + i)
		store.Put(mustDecision(ip+"|"+ja4, TierRisky, 0.1, now.Add(10*time.Minute)))
	}

	for i := 0; i < 100_000; i += 7 {
		key := decisionKeyForIndex(i)
		store.Put(mustDecision(key, TierDangerous, 0.9, now.Add(time.Hour)))
	}

	if store.Len() != 100_000 {
		t.Fatalf("Len() = %d, want 100000", store.Len())
	}
}

func TestStore_UnsetMaxEntriesUsesDefault(t *testing.T) {
	store := NewStore(0)
	if store.maxEntries != DefaultMaxEntries {
		t.Fatalf("NewStore(0) maxEntries = %d, want %d", store.maxEntries, DefaultMaxEntries)
	}
	store.SetMaxEntries(10)
	store.SetMaxEntries(0)
	if store.maxEntries != DefaultMaxEntries {
		t.Fatalf("SetMaxEntries(0) maxEntries = %d, want %d", store.maxEntries, DefaultMaxEntries)
	}
}

func decisionKeyForIndex(i int) string {
	ip := []byte{10, 0, byte(i / 256 % 256), byte(i % 256)}
	return net.IP(ip).String() + "|ja4-" + strconv.Itoa(i)
}

func TestStore_SweepRemovesOnlyExpiredEntries(t *testing.T) {
	now := time.Now()
	store := NewStore(10_000)
	suffixes := []string{"ja4-a", "-", "*"}
	live := map[string]bool{}
	for i := 0; i < 3000; i++ {
		ip := net.IP([]byte{10, 1, byte(i / 256), byte(i % 256)}).String()
		key := ip + "|" + suffixes[i%3]
		expires := now.Add(time.Hour)
		if i%2 == 0 {
			expires = now.Add(-time.Minute)
		} else {
			live[key] = true
		}
		store.Put(Decision{Key: key, Tier: TierDangerous, ExpiresAt: expires})
	}

	store.Sweep(now)

	if store.Len() != len(live) {
		t.Fatalf("Len() after sweep = %d, want %d", store.Len(), len(live))
	}
	for ip, inner := range store.byIP {
		if len(inner) == 0 {
			t.Fatalf("empty inner map left for %s", ip)
		}
		for suffix, entry := range inner {
			if !live[ip+"|"+suffix] {
				t.Fatalf("expired entry %s|%s survived the sweep", ip, suffix)
			}
			if store.heap[entry.index] != entry {
				t.Fatalf("heap index of %s|%s is stale", ip, suffix)
			}
		}
	}
	for i := 1; i < len(store.heap); i++ {
		if store.heap.Less(i, (i-1)/2) {
			t.Fatalf("heap property broken at %d", i)
		}
	}
	if _, ok := store.Resolve("10.1.0.1", "", now); !ok {
		t.Fatal("a live plain-HTTP decision no longer resolves after the sweep")
	}
	if _, ok := store.Resolve("10.1.0.0", "ja4-a", now); ok {
		t.Fatal("an expired TLS decision still resolves after the sweep")
	}
	if _, ok := store.Resolve("10.1.0.3", "ja4-a", now); !ok {
		t.Fatal("a live TLS decision no longer resolves after the sweep")
	}
}
