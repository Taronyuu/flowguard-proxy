package decisions

import (
	"container/heap"
	"strings"
	"sync"
	"time"
)

const DefaultMaxEntries = 100_000

type storeEntry struct {
	decision Decision
	index    int
}

type expiryHeap []*storeEntry

func (h expiryHeap) Len() int { return len(h) }

func (h expiryHeap) Less(i, j int) bool {
	return h[i].decision.ExpiresAt.Before(h[j].decision.ExpiresAt)
}

func (h expiryHeap) Swap(i, j int) {
	h[i], h[j] = h[j], h[i]
	h[i].index = i
	h[j].index = j
}

func (h *expiryHeap) Push(x any) {
	entry := x.(*storeEntry)
	entry.index = len(*h)
	*h = append(*h, entry)
}

func (h *expiryHeap) Pop() any {
	old := *h
	n := len(old)
	entry := old[n-1]
	old[n-1] = nil
	*h = old[:n-1]
	return entry
}

type Store struct {
	mu         sync.RWMutex
	byIP       map[string]map[string]*storeEntry
	heap       expiryHeap
	maxEntries int
}

func NewStore(maxEntries int) *Store {
	if maxEntries <= 0 {
		maxEntries = DefaultMaxEntries
	}
	return &Store{
		byIP:       make(map[string]map[string]*storeEntry),
		maxEntries: maxEntries,
	}
}

func splitKey(key string) (string, string) {
	idx := strings.LastIndexByte(key, '|')
	return key[:idx], key[idx+1:]
}

func (s *Store) SetMaxEntries(n int) {
	if n <= 0 {
		n = DefaultMaxEntries
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.maxEntries = n
	s.evictOverCapLocked()
}

func (s *Store) Put(d Decision) {
	s.mu.Lock()
	defer s.mu.Unlock()

	ip, suffix := splitKey(d.Key)
	inner := s.byIP[ip]
	if inner == nil {
		inner = make(map[string]*storeEntry)
		s.byIP[ip] = inner
	}

	if existing, ok := inner[suffix]; ok {
		existing.decision = d
		heap.Fix(&s.heap, existing.index)
		return
	}

	entry := &storeEntry{decision: d}
	inner[suffix] = entry
	heap.Push(&s.heap, entry)
	s.evictOverCapLocked()
}

func (s *Store) Delete(key string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.deleteLocked(key)
}

func (s *Store) deleteLocked(key string) {
	ip, suffix := splitKey(key)
	if entry, ok := s.byIP[ip][suffix]; ok {
		s.removeLocked(entry)
	}
}

func (s *Store) removeLocked(entry *storeEntry) {
	heap.Remove(&s.heap, entry.index)
	ip, suffix := splitKey(entry.decision.Key)
	inner := s.byIP[ip]
	delete(inner, suffix)
	if len(inner) == 0 {
		delete(s.byIP, ip)
	}
}

func (s *Store) evictOverCapLocked() {
	for len(s.heap) > s.maxEntries {
		s.removeLocked(s.heap[0])
	}
}

func (s *Store) ReplaceAll(decisions map[string]Decision) {
	byIP := make(map[string]map[string]*storeEntry)
	h := make(expiryHeap, 0, len(decisions))
	for key, d := range decisions {
		ip, suffix := splitKey(key)
		inner := byIP[ip]
		if inner == nil {
			inner = make(map[string]*storeEntry)
			byIP[ip] = inner
		}
		entry := &storeEntry{decision: d, index: len(h)}
		inner[suffix] = entry
		h = append(h, entry)
	}
	heap.Init(&h)

	s.mu.Lock()
	defer s.mu.Unlock()
	s.byIP = byIP
	s.heap = h
	s.evictOverCapLocked()
}

func (s *Store) Clear() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.byIP = make(map[string]map[string]*storeEntry)
	s.heap = nil
}

func (s *Store) Len() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.heap)
}

const sweepBatch = 1000

func (s *Store) Sweep(now time.Time) {
	for s.sweepBatch(now) {
	}
}

func (s *Store) sweepBatch(now time.Time) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	for i := 0; i < sweepBatch; i++ {
		if len(s.heap) == 0 || s.heap[0].decision.ExpiresAt.After(now) {
			return false
		}
		s.removeLocked(s.heap[0])
	}
	return true
}

func (s *Store) Resolve(ip, ja4 string, now time.Time) (Decision, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	inner := s.byIP[ip]
	if inner == nil {
		return Decision{}, false
	}

	if ja4 != "" {
		entry, ok := inner[ja4]
		if !ok || !entry.decision.ExpiresAt.After(now) {
			return Decision{}, false
		}
		return entry.decision, true
	}

	var best Decision
	found := false
	if entry, ok := inner["-"]; ok && entry.decision.ExpiresAt.After(now) {
		best = entry.decision
		found = true
	}
	if entry, ok := inner["*"]; ok && entry.decision.ExpiresAt.After(now) {
		if !found || tierRank(entry.decision.Tier) > tierRank(best.Tier) {
			best = entry.decision
			found = true
		}
	}
	return best, found
}
