package config

import "testing"

func TestManagerLoad_S_decision_feed_config_omitted(t *testing.T) {
	configPath := writeTestConfig(t, `{
  "rules": {},
  "actions": {}
}`)

	manager, err := loadTestManager(configPath)
	if err != nil {
		t.Fatalf("expected config without decisions to load: %v", err)
	}

	if manager.GetConfig().DecisionsActive() {
		t.Fatal("expected the feed to be off when decisions is omitted")
	}
}

func TestManagerLoad_S_decision_feed_disabled_or_no_socket(t *testing.T) {
	tests := []struct {
		name string
		body string
	}{
		{
			name: "disabled with socket path",
			body: `{"decisions": {"enabled": false, "socket_path": "/run/waf-scorer/decisions.sock"}}`,
		},
		{
			name: "enabled without socket path",
			body: `{"decisions": {"enabled": true}}`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			configPath := writeTestConfig(t, tt.body)
			manager, err := loadTestManager(configPath)
			if err != nil {
				t.Fatalf("expected config to load: %v", err)
			}
			if manager.GetConfig().DecisionsActive() {
				t.Fatal("expected the feed to count as off")
			}
		})
	}
}

func TestDecisionsSettings_UnsetMaxEntriesIsZero(t *testing.T) {
	cfg := &Config{Decisions: &DecisionsConfig{Enabled: true, SocketPath: "/run/waf-scorer/decisions.sock"}}

	socketPath, scorerUID, maxEntries := cfg.DecisionsSettings()
	if socketPath != "/run/waf-scorer/decisions.sock" {
		t.Fatalf("socketPath = %q", socketPath)
	}
	if scorerUID != 0 {
		t.Fatalf("scorerUID = %d, want 0 default", scorerUID)
	}
	if maxEntries != 0 {
		t.Fatalf("maxEntries = %d, want 0 so the store applies its own default", maxEntries)
	}
	if !cfg.DecisionsActive() {
		t.Fatal("expected the feed to be active with enabled=true and a socket path")
	}
}

func TestDecisionsSettings_NilConfig(t *testing.T) {
	var cfg *Config

	if cfg.DecisionsActive() {
		t.Fatal("expected a nil config to count as off")
	}

	_, _, maxEntries := cfg.DecisionsSettings()
	if maxEntries != 0 {
		t.Fatalf("maxEntries = %d, want 0 so the store applies its own default", maxEntries)
	}
}

func TestDecisionsSettings_ConfiguredMaxEntries(t *testing.T) {
	cfg := &Config{Decisions: &DecisionsConfig{Enabled: true, SocketPath: "/run/waf-scorer/decisions.sock", MaxEntries: 5000}}

	if _, _, maxEntries := cfg.DecisionsSettings(); maxEntries != 5000 {
		t.Fatalf("maxEntries = %d, want 5000", maxEntries)
	}
}
