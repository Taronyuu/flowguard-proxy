package proxy

import (
	"fmt"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"flowguard/config"
	"flowguard/decisions"
	"flowguard/middleware"
)

func newTestDecisionsManager(t *testing.T) (*Manager, *decisions.Store) {
	t.Helper()
	store := decisions.NewStore(10)
	dm := middleware.NewDecisionMiddleware(store)
	sub := decisions.NewSubscriber(store)
	p := &Manager{
		config:             &Config{Verbose: false},
		decisionMiddleware: dm,
		decisionSubscriber: sub,
	}
	return p, store
}

func TestApplyDecisionsConfig_S_decision_feed_kill_switch(t *testing.T) {
	socketPath := filepath.Join(t.TempDir(), "decisions.sock")
	listener, err := net.Listen("unix", socketPath)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer listener.Close()

	p, store := newTestDecisionsManager(t)
	defer p.decisionSubscriber.Stop()

	enabledCfg := &config.Config{Decisions: &config.DecisionsConfig{
		Enabled:    true,
		SocketPath: socketPath,
		ScorerUID:  os.Getuid(),
	}}
	p.applyDecisionsConfig(enabledCfg)

	conn, err := listener.Accept()
	if err != nil {
		t.Fatalf("accept: %v", err)
	}
	defer conn.Close()

	if _, err := conn.Write([]byte(`{"type":"sync_begin"}` + "\n")); err != nil {
		t.Fatalf("write: %v", err)
	}
	if _, err := conn.Write([]byte(`{"type":"put","decision":{"key":"203.0.113.5|ja4-a","tier":"risky","score":0.1,"expires_at":"` + time.Now().Add(time.Hour).UTC().Format(time.RFC3339) + `","reason":"t","model_version":"v1"}}` + "\n")); err != nil {
		t.Fatalf("write: %v", err)
	}
	if _, err := conn.Write([]byte(`{"type":"sync_end"}` + "\n")); err != nil {
		t.Fatalf("write: %v", err)
	}

	deadline := time.Now().Add(time.Second)
	for store.Len() == 0 && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	if store.Len() != 1 {
		t.Fatalf("Len() = %d, want 1 after enabling the feed", store.Len())
	}
	if !p.decisionMiddleware.Active() {
		t.Fatal("expected the decision middleware to be active")
	}

	disabledCfg := &config.Config{Decisions: &config.DecisionsConfig{Enabled: false}}
	p.applyDecisionsConfig(disabledCfg)

	if store.Len() != 0 {
		t.Fatalf("Len() = %d, want 0: the kill switch must clear the store without a restart", store.Len())
	}
	if p.decisionMiddleware.Active() {
		t.Fatal("expected the decision middleware to be inactive after disabling the feed")
	}

	p.applyDecisionsConfig(enabledCfg)
	if !p.decisionMiddleware.Active() {
		t.Fatal("expected re-enabling the feed to reactivate the decision middleware")
	}
}

func TestLiveConfigReload_S_decision_feed_kill_switch(t *testing.T) {
	socketPath := filepath.Join(t.TempDir(), "decisions.sock")
	listener, err := net.Listen("unix", socketPath)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer listener.Close()

	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				c.Write([]byte(`{"type":"sync_begin"}` + "\n"))
				c.Write([]byte(`{"type":"put","decision":{"key":"203.0.113.9|ja4-b","tier":"risky","score":0.2,"expires_at":"` + time.Now().Add(time.Hour).UTC().Format(time.RFC3339) + `","reason":"t","model_version":"v1"}}` + "\n"))
				c.Write([]byte(`{"type":"sync_end"}` + "\n"))
				<-make(chan struct{})
			}(conn)
		}
	}()

	configPath := filepath.Join(t.TempDir(), "config.json")
	enabledBody := `{"id":"host-cfg","decisions":{"enabled":true,"socket_path":"` + socketPath + `","scorer_uid":` + itoa(os.Getuid()) + `}}`
	if err := os.WriteFile(configPath, []byte(enabledBody), 0o644); err != nil {
		t.Fatalf("write config: %v", err)
	}

	configMgr, err := config.NewManager(configPath, "FlowGuard/test", "test", "", false)
	if err != nil {
		t.Fatalf("new config manager: %v", err)
	}
	defer configMgr.Stop()

	store := decisions.NewStore(10)
	dm := middleware.NewDecisionMiddleware(store)
	sub := decisions.NewSubscriber(store)
	defer sub.Stop()
	p := &Manager{
		config:             &Config{Verbose: false},
		decisionMiddleware: dm,
		decisionSubscriber: sub,
	}

	p.applyDecisionsConfig(configMgr.GetConfig())
	configMgr.OnChange(func(newConfig *config.Config) {
		p.applyDecisionsConfig(newConfig)
	})
	configMgr.StartWatcher()

	deadline := time.Now().Add(2 * time.Second)
	for store.Len() == 0 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if store.Len() == 0 {
		t.Fatal("expected the initial sync to populate the store")
	}

	disabledBody := `{"id":"host-cfg-feed-off","decisions":{"enabled":false,"socket_path":"` + socketPath + `","scorer_uid":` + itoa(os.Getuid()) + `}}`
	if err := os.WriteFile(configPath, []byte(disabledBody), 0o644); err != nil {
		t.Fatalf("rewrite config: %v", err)
	}

	deadline = time.Now().Add(2 * time.Second)
	for store.Len() != 0 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if store.Len() != 0 {
		t.Fatalf("Len() = %d, want 0: a live config-file reload must clear the store without a restart", store.Len())
	}
	if dm.Active() {
		t.Fatal("expected the decision middleware to be inactive after the live reload disabled the feed")
	}
}

func itoa(n int) string {
	return fmt.Sprintf("%d", n)
}
