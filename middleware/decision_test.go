package middleware

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"flowguard/config"
	"flowguard/decisions"
	"flowguard/logger"
)

func withClientIPForTest(r *http.Request, ip string) *http.Request {
	ctx := context.WithValue(r.Context(), ContextKeyClientIP, ip)
	return r.WithContext(ctx)
}

func TestDecisionMiddleware_ResolvesRequestDownstream(t *testing.T) {
	store := decisions.NewStore(10)
	store.Put(decisions.Decision{
		Key:       "203.0.113.5|ja4-a",
		Tier:      decisions.TierDangerous,
		Score:     0.9,
		ExpiresAt: time.Now().Add(time.Hour),
		Reason:    "test",
	})

	req := httptest.NewRequest(http.MethodGet, "https://example.com/", nil)
	req = req.WithContext(ContextWithJA4Fingerprint(req.Context(), "ja4-a"))
	req = withClientIPForTest(req, "203.0.113.5")

	dm := NewDecisionMiddleware(store)
	dm.SetActive(true)

	var seenTier string
	var seenHas bool
	dm.Handle(httptest.NewRecorder(), req, http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		seenTier, seenHas = GetDecisionTier(r)
	}))

	if !seenHas || seenTier != decisions.TierDangerous {
		t.Fatalf("GetDecisionTier downstream = %q, %v, want dangerous", seenTier, seenHas)
	}
}

func TestDecisionMiddleware_InactiveSkipsResolution(t *testing.T) {
	store := decisions.NewStore(10)
	store.Put(decisions.Decision{
		Key:       "203.0.113.5|ja4-a",
		Tier:      decisions.TierDangerous,
		ExpiresAt: time.Now().Add(time.Hour),
	})

	req := httptest.NewRequest(http.MethodGet, "https://example.com/", nil)
	req = req.WithContext(ContextWithJA4Fingerprint(req.Context(), "ja4-a"))
	req = withClientIPForTest(req, "203.0.113.5")

	dm := NewDecisionMiddleware(store)

	var result *DecisionResolveResult
	dm.Handle(httptest.NewRecorder(), req, http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		result = GetDecisionResolveResult(r)
	}))

	if result != nil {
		t.Fatalf("expected no resolve result when the feed is inactive, got %#v", result)
	}
}

func TestRulesMiddleware_S_decision_rules_block_dangerous(t *testing.T) {
	store := decisions.NewStore(10)
	store.Put(decisions.Decision{
		Key:       "203.0.113.5|ja4-a",
		Tier:      decisions.TierDangerous,
		ExpiresAt: time.Now().Add(time.Hour),
	})

	req := httptest.NewRequest(http.MethodGet, "https://example.com/", nil)
	req = req.WithContext(ContextWithJA4Fingerprint(req.Context(), "ja4-a"))
	req = withClientIPForTest(req, "203.0.113.5")

	dm := NewDecisionMiddleware(store)
	dm.SetActive(true)
	var resolved *http.Request
	dm.Handle(httptest.NewRecorder(), req, http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		resolved = r
	}))

	rm := &RulesMiddleware{}
	match := config.MatchCondition{Type: "decision", Match: "equals", Value: "dangerous"}
	if !rm.evaluateMatch(resolved, &match) {
		t.Fatal("expected a decision equals dangerous match to match a dangerous request")
	}
}

func TestRulesMiddleware_S_decision_rules_challenge_risky_browsers(t *testing.T) {
	store := decisions.NewStore(10)
	store.Put(decisions.Decision{
		Key:       "203.0.113.5|ja4-a",
		Tier:      decisions.TierRisky,
		ExpiresAt: time.Now().Add(time.Hour),
	})

	newRequest := func(userAgent string) *http.Request {
		req := httptest.NewRequest(http.MethodGet, "https://example.com/", nil)
		req.Header.Set("User-Agent", userAgent)
		req = req.WithContext(ContextWithJA4Fingerprint(req.Context(), "ja4-a"))
		req = withClientIPForTest(req, "203.0.113.5")

		dm := NewDecisionMiddleware(store)
		dm.SetActive(true)
		var resolved *http.Request
		dm.Handle(httptest.NewRecorder(), req, http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
			resolved = r
		}))
		return resolved
	}

	rm := &RulesMiddleware{}
	conditions := &config.RuleConditions{
		Operator: "AND",
		Matches: []config.MatchCondition{
			{Type: "decision", Match: "equals", Value: "risky"},
			{Type: "user-agent", Match: "contains", Value: "Mozilla"},
		},
	}

	browserReq := newRequest("Mozilla/5.0 (compatible browser)")
	if !rm.matchesConditions(browserReq, conditions) {
		t.Fatal("expected a risky browser request to match")
	}

	nonBrowserReq := newRequest("curl/8.0")
	if rm.matchesConditions(nonBrowserReq, conditions) {
		t.Fatal("expected a risky non-browser request not to match")
	}
}

func TestLoggingMiddleware_S_decision_rules_logged_decision(t *testing.T) {
	store := decisions.NewStore(10)
	expiresAt := time.Now().Add(time.Hour).Truncate(time.Second)
	store.Put(decisions.Decision{
		Key:          "203.0.113.5|*",
		Tier:         decisions.TierDangerous,
		Score:        0.91,
		ExpiresAt:    expiresAt,
		Reason:       "2 requests over threshold",
		ModelVersion: "ettin17m-1",
	})

	logPath := filepath.Join(t.TempDir(), "requests.log")
	loggerManager := logger.NewManager("FlowGuard/test")
	if err := loggerManager.UpdateSinks(map[string]map[string]interface{}{
		"decision_test": {"type": "file", "path": logPath},
	}); err != nil {
		t.Fatalf("configure test logger: %v", err)
	}
	lm := &LoggingMiddleware{loggerManager: loggerManager, enabled: true, version: "test"}

	req := httptest.NewRequest(http.MethodGet, "http://example.com/", nil)
	req = withClientIPForTest(req, "203.0.113.5")

	dm := NewDecisionMiddleware(store)
	dm.SetActive(true)

	w := httptest.NewRecorder()
	dm.Handle(w, req, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		lm.Handle(w, r, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		}))
	}))

	if err := loggerManager.Close(); err != nil {
		t.Fatalf("close test logger: %v", err)
	}

	entry := readLoggedDecision(t, logPath)
	if entry.Decision == nil {
		t.Fatal("expected a decision object in the log entry")
	}
	if entry.Decision.Tier != "dangerous" || entry.Decision.Key != "203.0.113.5|*" {
		t.Fatalf("unexpected decision info: %#v", entry.Decision)
	}
	if entry.Decision.Score != 0.91 || entry.Decision.ModelVersion != "ettin17m-1" {
		t.Fatalf("unexpected decision score/model: %#v", entry.Decision)
	}
}

func TestLoggingMiddleware_S_decision_rules_no_decision_logged(t *testing.T) {
	store := decisions.NewStore(10)

	logPath := filepath.Join(t.TempDir(), "requests.log")
	loggerManager := logger.NewManager("FlowGuard/test")
	if err := loggerManager.UpdateSinks(map[string]map[string]interface{}{
		"decision_test": {"type": "file", "path": logPath},
	}); err != nil {
		t.Fatalf("configure test logger: %v", err)
	}
	lm := &LoggingMiddleware{loggerManager: loggerManager, enabled: true, version: "test"}

	req := httptest.NewRequest(http.MethodGet, "http://example.com/", nil)
	req = withClientIPForTest(req, "198.51.100.1")

	dm := NewDecisionMiddleware(store)
	dm.SetActive(true)

	w := httptest.NewRecorder()
	dm.Handle(w, req, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		lm.Handle(w, r, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		}))
	}))

	if err := loggerManager.Close(); err != nil {
		t.Fatalf("close test logger: %v", err)
	}

	entry := readLoggedDecision(t, logPath)
	if entry.Decision != nil {
		t.Fatalf("expected no decision object, got %#v", entry.Decision)
	}
	if entry.ResolveUS == nil {
		t.Fatal("expected decision_resolve_us to be logged while the feed is active")
	}
}

type loggedDecisionEntry struct {
	Decision  *RequestLogEntryDecisionInfo `json:"decision"`
	ResolveUS *int64                       `json:"decision_resolve_us"`
}

func readLoggedDecision(t *testing.T, logPath string) loggedDecisionEntry {
	t.Helper()
	data, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatalf("read request log: %v", err)
	}
	lines := strings.Split(strings.TrimSpace(string(data)), "\n")
	if len(lines) != 1 {
		t.Fatalf("log lines = %d, want 1", len(lines))
	}
	var entry loggedDecisionEntry
	if err := json.Unmarshal([]byte(lines[0]), &entry); err != nil {
		t.Fatalf("decode request log: %v", err)
	}
	return entry
}

func resolvedRequestWithTier(t *testing.T, tier string) *http.Request {
	t.Helper()
	store := decisions.NewStore(10)
	if tier != "" {
		store.Put(decisions.Decision{
			Key:       "203.0.113.5|ja4-a",
			Tier:      tier,
			ExpiresAt: time.Now().Add(time.Hour),
		})
	}

	req := httptest.NewRequest(http.MethodGet, "https://example.com/", nil)
	req = req.WithContext(ContextWithJA4Fingerprint(req.Context(), "ja4-a"))
	req = withClientIPForTest(req, "203.0.113.5")

	dm := NewDecisionMiddleware(store)
	dm.SetActive(true)
	var resolved *http.Request
	dm.Handle(httptest.NewRecorder(), req, http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		resolved = r
	}))
	return resolved
}

func TestRulesMiddleware_DecisionMatchOperators(t *testing.T) {
	states := []string{decisions.TierDangerous, decisions.TierRisky, ""}
	tests := []struct {
		name  string
		match config.MatchCondition
		want  [3]bool
	}{
		{"equals", config.MatchCondition{Type: "decision", Match: "equals", Value: "dangerous"}, [3]bool{true, false, false}},
		{"not-equals", config.MatchCondition{Type: "decision", Match: "not-equals", Value: "dangerous"}, [3]bool{false, true, false}},
		{"in", config.MatchCondition{Type: "decision", Match: "in", Values: []string{"dangerous"}}, [3]bool{true, false, false}},
		{"not-in", config.MatchCondition{Type: "decision", Match: "not-in", Values: []string{"dangerous"}}, [3]bool{false, true, false}},
		{"exists", config.MatchCondition{Type: "decision", Match: "exists"}, [3]bool{true, true, false}},
		{"missing", config.MatchCondition{Type: "decision", Match: "missing"}, [3]bool{false, false, true}},
	}

	rm := &RulesMiddleware{}
	for _, tt := range tests {
		for i, tier := range states {
			match := tt.match
			got := rm.evaluateMatch(resolvedRequestWithTier(t, tier), &match)
			if got != tt.want[i] {
				t.Errorf("%s with tier %q: got %v, want %v", tt.name, tier, got, tt.want[i])
			}
		}
	}
}
