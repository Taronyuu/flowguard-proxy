package logger

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"time"
)

const FlowGuardIngestCapability = "log_ingest_v1"

// FlowGuardIngestSink delivers structured logs through the shared memory writer.
type FlowGuardIngestSink struct {
	name       string
	config     FlowGuardIngestSinkConfig
	configHash string
	userAgent  string
	client     *http.Client
	writer     *asyncBatchWriter

	// Only the writer goroutine accesses the prepared requests, including during drain.
	pending []ingestRequest
	next    int
}

type FlowGuardIngestSinkConfig struct {
	URL             string `json:"url"`
	ProtocolVersion int    `json:"protocol_version"`
	CredentialID    string `json:"credential_id"`
	Secret          string `json:"secret"`
}

func init() {
	RegisterSinkFactory("flowguard_ingest", NewFlowGuardIngestSink)
}

func NewFlowGuardIngestSink(name string, config map[string]interface{}, userAgent string) (Sink, error) {
	configJSON, err := json.Marshal(config)
	if err != nil {
		return nil, fmt.Errorf("failed to encode flowguard ingest configuration")
	}

	var sinkConfig FlowGuardIngestSinkConfig
	if err := json.Unmarshal(configJSON, &sinkConfig); err != nil {
		return nil, fmt.Errorf("invalid flowguard ingest configuration")
	}

	if err := sinkConfig.validate(); err != nil {
		return nil, err
	}

	sink := &FlowGuardIngestSink{
		name:       name,
		config:     sinkConfig,
		configHash: computeConfigHash(config),
		userAgent:  userAgent,
		client: &http.Client{
			Timeout: 30 * time.Second,
			CheckRedirect: func(*http.Request, []*http.Request) error {
				return http.ErrUseLastResponse
			},
		},
	}

	options := defaultAsyncBatchWriterOptions()
	options.onBatchReleased = sink.releaseBatch
	sink.writer = newAsyncBatchWriterWithOptions("flowguard_ingest", name, sink.sendBatch, options)

	return sink, nil
}

func (c FlowGuardIngestSinkConfig) validate() error {
	endpoint, err := url.Parse(c.URL)
	if err != nil || endpoint.Scheme != "https" || endpoint.Hostname() == "" ||
		endpoint.User != nil || endpoint.RawQuery != "" || endpoint.ForceQuery || endpoint.Fragment != "" {
		return fmt.Errorf("flowguard ingest requires an HTTPS endpoint without user info, query, or fragment")
	}

	if c.ProtocolVersion != 1 {
		return fmt.Errorf("unsupported flowguard ingest protocol version")
	}

	if !ingestHexID(c.CredentialID) {
		return fmt.Errorf("invalid flowguard ingest identity or credential ID")
	}

	secret, err := base64.RawURLEncoding.Strict().DecodeString(c.Secret)
	if err != nil || len(secret) != 32 || base64.RawURLEncoding.EncodeToString(secret) != c.Secret {
		return fmt.Errorf("invalid flowguard ingest secret encoding")
	}

	return nil
}

func (s *FlowGuardIngestSink) Write(entry *LogEntry) error {
	return s.writer.Write(entry)
}

func (s *FlowGuardIngestSink) Close() error {
	s.writer.Close()
	return nil
}

func (s *FlowGuardIngestSink) Name() string {
	return s.name
}

func (s *FlowGuardIngestSink) ConfigHash() string {
	return s.configHash
}

func (s *FlowGuardIngestSink) releaseBatch() {
	s.pending = nil
	s.next = 0
}

func (s *FlowGuardIngestSink) sendBatch(ctx context.Context, entries []*LogEntry) error {
	if len(entries) == 0 {
		return nil
	}

	if s.pending == nil {
		requests, err := prepareIngestRequests(entries, s.config.CredentialID)
		if err != nil {
			return err
		}

		s.pending = requests
	}

	for s.next < len(s.pending) {
		if s.pending[s.next].preparedAt == 0 {
			s.pending[s.next].preparedAt = time.Now().UnixMicro()
		}

		if err := s.sendRequest(ctx, s.pending[s.next]); err != nil {
			return err
		}

		s.next++
	}

	return nil
}

func (s *FlowGuardIngestSink) sendRequest(ctx context.Context, batch ingestRequest) error {
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, s.config.URL, bytes.NewReader(batch.body))
	if err != nil {
		return fmt.Errorf("failed to create flowguard ingest request")
	}

	request.Header.Set("Authorization", "Bearer fgi1."+s.config.CredentialID+"."+s.config.Secret)
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Content-Encoding", "gzip")
	request.Header.Set("X-FlowGuard-Batch-SHA256", batch.digest)
	request.Header.Set("X-FlowGuard-Prepared-At", strconv.FormatInt(batch.preparedAt, 10))
	if s.userAgent != "" {
		request.Header.Set("User-Agent", s.userAgent)
	}

	response, err := s.client.Do(request)
	if err != nil {
		return fmt.Errorf("flowguard ingest request failed")
	}
	defer response.Body.Close()

	if response.StatusCode != http.StatusOK {
		return fmt.Errorf("flowguard ingest returned HTTP %d", response.StatusCode)
	}

	body, err := io.ReadAll(io.LimitReader(response.Body, ingestReceiptMaxBytes+1))
	if err != nil || len(body) > ingestReceiptMaxBytes {
		return fmt.Errorf("invalid flowguard ingest receipt size")
	}

	var receipt ingestReceipt
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&receipt); err != nil {
		return fmt.Errorf("invalid flowguard ingest receipt")
	}

	if decoder.Decode(new(any)) != io.EOF || !receipt.matches(batch, s.config.CredentialID) {
		return fmt.Errorf("flowguard ingest receipt does not match batch")
	}

	return nil
}

type ingestReceipt struct {
	ProtocolVersion      int    `json:"protocol_version"`
	State                string `json:"state"`
	Outcome              string `json:"outcome"`
	IdentityGeneration   string `json:"identity_generation"`
	BatchID              string `json:"batch_id"`
	BatchSHA256          string `json:"batch_sha256"`
	RequestID            string `json:"request_id"`
	Code                 string `json:"code"`
	Retryable            *bool  `json:"retryable"`
	EventCount           int    `json:"event_count"`
	RawBytes             string `json:"raw_bytes"`
	AccountingVersion    string `json:"accounting_version"`
	NormalizationVersion string `json:"normalization_version"`
}

func (r ingestReceipt) matches(batch ingestRequest, generation string) bool {
	return r.ProtocolVersion == 1 && r.State == "committed" && r.Outcome == "committed" &&
		r.IdentityGeneration == generation && r.BatchID == batch.id && r.BatchSHA256 == batch.digest &&
		ingestHexID(r.RequestID) && r.Code == "complete" && r.Retryable != nil && !*r.Retryable &&
		r.EventCount == batch.events && r.RawBytes == strconv.Itoa(batch.rawBytes) &&
		r.AccountingVersion == "flowguard-json-v1" && r.NormalizationVersion == "flowguard-event-v1"
}
