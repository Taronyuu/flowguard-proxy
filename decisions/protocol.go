package decisions

type wireMessage struct {
	Type     string        `json:"type"`
	Decision *wireDecision `json:"decision,omitempty"`
	Key      string        `json:"key,omitempty"`
}

type wireDecision struct {
	Key          string  `json:"key"`
	Tier         string  `json:"tier"`
	Score        float64 `json:"score"`
	ExpiresAt    string  `json:"expires_at"`
	Reason       string  `json:"reason"`
	ModelVersion string  `json:"model_version"`
}
