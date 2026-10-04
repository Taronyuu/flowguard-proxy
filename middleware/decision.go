package middleware

import (
	"context"
	"net/http"
	"sync/atomic"
	"time"

	"flowguard/decisions"
)

const ContextKeyDecisionResult contextKey = "decision_result"

type DecisionResolveResult struct {
	Decision  *decisions.Decision
	ResolveUS int64
}

type DecisionMiddleware struct {
	store  *decisions.Store
	active atomic.Bool
}

func NewDecisionMiddleware(store *decisions.Store) *DecisionMiddleware {
	return &DecisionMiddleware{store: store}
}

func (dm *DecisionMiddleware) SetActive(active bool) {
	dm.active.Store(active)
}

func (dm *DecisionMiddleware) Active() bool {
	return dm.active.Load()
}

func (dm *DecisionMiddleware) Handle(w http.ResponseWriter, r *http.Request, next http.Handler) {
	if !dm.active.Load() {
		next.ServeHTTP(w, r)
		return
	}

	start := time.Now()
	clientIP := GetClientIP(r)
	ja4 := GetJA4Fingerprint(r)

	decision, found := dm.store.Resolve(clientIP, ja4, start)
	result := &DecisionResolveResult{ResolveUS: time.Since(start).Microseconds()}
	if found {
		result.Decision = &decision
	}

	ctx := context.WithValue(r.Context(), ContextKeyDecisionResult, result)
	next.ServeHTTP(w, r.WithContext(ctx))
}

func (dm *DecisionMiddleware) Stop() {}

func GetDecisionResolveResult(r *http.Request) *DecisionResolveResult {
	if result, ok := r.Context().Value(ContextKeyDecisionResult).(*DecisionResolveResult); ok {
		return result
	}
	return nil
}

func GetDecisionTier(r *http.Request) (string, bool) {
	result := GetDecisionResolveResult(r)
	if result == nil || result.Decision == nil {
		return "", false
	}
	return result.Decision.Tier, true
}
