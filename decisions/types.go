package decisions

import (
	"fmt"
	"net"
	"strings"
	"time"
)

const (
	TierRisky     = "risky"
	TierDangerous = "dangerous"
)

const maxDecisionLead = 25 * time.Hour

type Decision struct {
	Key          string
	Tier         string
	Score        float64
	ExpiresAt    time.Time
	Reason       string
	ModelVersion string
}

func validTier(tier string) bool {
	return tier == TierRisky || tier == TierDangerous
}

func validKeyForm(key string) bool {
	idx := strings.LastIndex(key, "|")
	if idx <= 0 || idx == len(key)-1 {
		return false
	}
	return net.ParseIP(key[:idx]) != nil
}

func decodeDecision(w *wireDecision, now time.Time) (Decision, error) {
	if w == nil || w.Key == "" {
		return Decision{}, fmt.Errorf("put message missing decision")
	}
	if !validKeyForm(w.Key) {
		return Decision{}, fmt.Errorf("invalid key form %q", w.Key)
	}
	if !validTier(w.Tier) {
		return Decision{}, fmt.Errorf("unknown tier %q for key %q", w.Tier, w.Key)
	}
	expiresAt, err := time.Parse(time.RFC3339, w.ExpiresAt)
	if err != nil {
		return Decision{}, fmt.Errorf("invalid expires_at %q: %w", w.ExpiresAt, err)
	}
	if expiresAt.Sub(now) > maxDecisionLead {
		return Decision{}, fmt.Errorf("expires_at %q is more than %s ahead", w.ExpiresAt, maxDecisionLead)
	}

	return Decision{
		Key:          w.Key,
		Tier:         w.Tier,
		Score:        w.Score,
		ExpiresAt:    expiresAt,
		Reason:       w.Reason,
		ModelVersion: w.ModelVersion,
	}, nil
}

func tierRank(tier string) int {
	switch tier {
	case TierDangerous:
		return 2
	case TierRisky:
		return 1
	default:
		return 0
	}
}
