package config

func (c *Config) DecisionsActive() bool {
	return c != nil && c.Decisions != nil && c.Decisions.Enabled && c.Decisions.SocketPath != ""
}

func (c *Config) DecisionsSettings() (socketPath string, scorerUID int, maxEntries int) {
	if c == nil || c.Decisions == nil {
		return "", 0, 0
	}
	return c.Decisions.SocketPath, c.Decisions.ScorerUID, c.Decisions.MaxEntries
}
