package logger

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"reflect"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestFlowGuardIngestConfigValidation(t *testing.T) {
	cases := []struct {
		name  string
		field string
		value any
	}{
		{name: "insecure endpoint", field: "url", value: "http://logs.example.invalid/v1/ingest"},
		{name: "embedded credentials", field: "url", value: "https://private:password@logs.example.invalid/v1/ingest"},
		{name: "query", field: "url", value: "https://logs.example.invalid/v1/ingest?secret=private"},
		{name: "fragment", field: "url", value: "https://logs.example.invalid/v1/ingest#private"},
		{name: "protocol", field: "protocol_version", value: 2},
		{name: "credential", field: "credential_id", value: "private-invalid-credential"},
		{name: "secret", field: "secret", value: "private-invalid-secret"},
	}

	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			config := ingestTestConfig()
			config[testCase.field] = testCase.value

			sink, err := CreateSink("shadow", config, "FlowGuard/test")
			if err == nil {
				sink.Close()
				t.Fatal("accepted invalid configuration")
			}

			if strings.Contains(err.Error(), "private") {
				t.Fatalf("configuration error disclosed input: %v", err)
			}
		})
	}
}

func TestFlowGuardIngestStructuredDeliveryAndClose(t *testing.T) {
	var captured ingestEnvelope
	sink := ingestTestSink(t, func(request *http.Request) (*http.Response, error) {
		if request.Method != http.MethodPost || request.URL.Path != "/v1/ingest" ||
			request.Header.Get("Content-Type") != "application/json" || request.Header.Get("User-Agent") != "FlowGuard/test" {
			t.Errorf("incorrect request metadata")
		}

		config := ingestTestConfig()
		wantAuth := "Bearer fgi1." + config["credential_id"].(string) + "." + config["secret"].(string)
		if request.Header.Get("Authorization") != wantAuth {
			t.Error("incorrect authentication")
		}

		body := ingestTestBody(t, request)
		if err := json.Unmarshal(body, &captured); err != nil {
			t.Error(err)
		}

		return ingestTestReceipt(t, request, body), nil
	}, asyncBatchWriterOptions{})

	entry := ingestTestEntry(2031, 6, 8)
	entry.Data["headers"] = map[string]any{"x.dynamic.name": []string{"<first>", "second"}}
	entry.Data["large_number"] = json.Number("9007199254740993")
	entry.Data["message"] = "snowman ☃ <&>"
	if err := sink.Write(entry); err != nil {
		t.Fatal(err)
	}

	if err := sink.Close(); err != nil {
		t.Fatal(err)
	}

	if len(captured.Events) != 1 || captured.IdentityGeneration != ingestTestConfig()["credential_id"] {
		t.Fatalf("unexpected envelope: %#v", captured)
	}

	var event ingestEvent
	if err := json.Unmarshal(captured.Events[0], &event); err != nil {
		t.Fatal(err)
	}

	if event.CapturedAt != strconv.FormatInt(time.Date(2031, 6, 8, 12, 0, 0, 0, time.UTC).UnixMicro(), 10) || !ingestHexID(event.ID) {
		t.Fatal("invalid event identity or captured timestamp")
	}

	if !bytes.Contains(event.Payload, []byte(`"large_number":9007199254740993`)) ||
		!bytes.Contains(event.Payload, []byte(`"headers":{"x.dynamic.name":["<first>","second"]}`)) ||
		!bytes.Contains(event.Payload, []byte(`"message":"snowman ☃ <&>"`)) {
		t.Fatalf("structured payload changed: %s", event.Payload)
	}

	if sink.pending != nil {
		t.Fatal("prepared batch retained after close")
	}

	if err := sink.Write(ingestTestEntry(2031, 6, 8)); !errors.Is(err, errSinkClosed) {
		t.Fatalf("write after close: %v", err)
	}
}

func TestFlowGuardIngestRetriesIdenticalRequestAndReleasesFailedBatch(t *testing.T) {
	for _, recover := range []bool{true, false} {
		t.Run(strconv.FormatBool(recover), func(t *testing.T) {
			var bodies [][]byte
			var digests []string
			released := make(chan struct{})
			options := asyncBatchWriterOptions{
				maxBatchEntries:   1,
				initialRetryDelay: time.Millisecond,
				onBatchReleased:   func() { close(released) },
			}

			sink := ingestTestSink(t, func(request *http.Request) (*http.Response, error) {
				body := ingestTestBody(t, request)
				bodies = append(bodies, body)
				digests = append(digests, request.Header.Get("X-FlowGuard-Batch-SHA256"))
				if len(bodies) == 1 || !recover {
					return nil, errors.New("synthetic lost acknowledgement")
				}

				return ingestTestReceipt(t, request, body), nil
			}, options)

			if err := sink.Write(ingestTestEntry(2031, 6, 8)); err != nil {
				t.Fatal(err)
			}
			waitIngestSignal(t, released)

			if len(bodies) != 2 || !bytes.Equal(bodies[0], bodies[1]) || digests[0] != digests[1] {
				t.Fatal("retry changed the request or exceeded the shared retry limit")
			}

			if sink.pending != nil {
				t.Fatal("prepared requests retained after writer released batch")
			}

			snapshot := sink.writer.diagnostics.snapshotAndReset()
			if recover && (snapshot.recoveries != 1 || snapshot.deliveryDropped != 0) {
				t.Fatalf("unexpected recovery diagnostics: %#v", snapshot)
			}
			if !recover && snapshot.deliveryDropped != 1 {
				t.Fatalf("failed batch was not counted: %#v", snapshot)
			}
		})
	}
}

func TestFlowGuardIngestRejectsUnmatchedReceipts(t *testing.T) {
	cases := []struct {
		name  string
		field string
		value any
	}{
		{name: "generation", field: "identity_generation", value: strings.Repeat("f", 32)},
		{name: "batch", field: "batch_id", value: strings.Repeat("f", 32)},
		{name: "digest", field: "batch_sha256", value: strings.Repeat("f", 64)},
		{name: "count", field: "event_count", value: 2},
		{name: "bytes", field: "raw_bytes", value: "0"},
		{name: "state", field: "state", value: "error"},
		{name: "outcome", field: "outcome", value: "unknown"},
		{name: "protocol", field: "protocol_version", value: 2},
		{name: "accounting", field: "accounting_version", value: "unknown"},
		{name: "normalization", field: "normalization_version", value: "unknown"},
		{name: "retryable", field: "retryable", value: true},
		{name: "missing retryable", field: "retryable", value: nil},
		{name: "request ID", field: "request_id", value: ""},
	}

	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			sink := ingestTestSink(t, func(request *http.Request) (*http.Response, error) {
				response := ingestTestReceipt(t, request, ingestTestBody(t, request))
				var receipt map[string]any
				if err := json.NewDecoder(response.Body).Decode(&receipt); err != nil {
					t.Fatal(err)
				}
				response.Body.Close()

				receipt[testCase.field] = testCase.value
				body, err := json.Marshal(receipt)
				if err != nil {
					t.Fatal(err)
				}
				response.Body = io.NopCloser(bytes.NewReader(body))

				return response, nil
			}, asyncBatchWriterOptions{})

			if err := sink.sendBatch(context.Background(), []*LogEntry{ingestTestEntry(2031, 6, 8)}); err == nil {
				t.Fatal("accepted mismatching receipt")
			}
			sink.releaseBatch()
		})
	}
}

func TestFlowGuardIngestRejectsInvalidHTTPResponses(t *testing.T) {
	cases := []struct {
		name   string
		status int
		body   string
	}{
		{name: "empty success", status: 200},
		{name: "no receipt", status: 204},
		{name: "redirect", status: 307, body: "private-backend-detail"},
		{name: "overload", status: 429, body: "private-backend-detail"},
		{name: "backend error", status: 503, body: "private-backend-detail"},
		{name: "oversized receipt", status: 200, body: strings.Repeat("x", ingestReceiptMaxBytes+1)},
		{name: "invalid JSON", status: 200, body: "private-backend-detail"},
	}

	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			sink := ingestTestSink(t, func(*http.Request) (*http.Response, error) {
				return &http.Response{
					StatusCode: testCase.status,
					Body:       io.NopCloser(strings.NewReader(testCase.body)),
					Header:     make(http.Header),
				}, nil
			}, asyncBatchWriterOptions{})

			err := sink.sendBatch(context.Background(), []*LogEntry{ingestTestEntry(2031, 6, 8)})
			if err == nil || strings.Contains(err.Error(), "private") {
				t.Fatalf("unsafe response handling: %v", err)
			}
			sink.releaseBatch()
		})
	}
}

func TestFlowGuardIngestSplitsDaysAndRetriesOnlyPendingRequest(t *testing.T) {
	var bodies [][]byte
	sink := ingestTestSink(t, func(request *http.Request) (*http.Response, error) {
		body := ingestTestBody(t, request)
		bodies = append(bodies, body)
		if len(bodies) == 2 {
			return nil, errors.New("synthetic second-day interruption")
		}

		return ingestTestReceipt(t, request, body), nil
	}, asyncBatchWriterOptions{})

	entries := []*LogEntry{ingestTestEntry(2031, 6, 8), ingestTestEntry(2031, 6, 9)}
	if err := sink.sendBatch(context.Background(), entries); err == nil {
		t.Fatal("expected interrupted second request")
	}
	if err := sink.sendBatch(context.Background(), entries); err != nil {
		t.Fatal(err)
	}

	if len(bodies) != 3 || !bytes.Equal(bodies[1], bodies[2]) || bytes.Equal(bodies[0], bodies[1]) {
		t.Fatal("day split or pending retry identity incorrect")
	}
	sink.releaseBatch()
}

func TestFlowGuardIngestReloadDrainsUnderOriginalIdentity(t *testing.T) {
	manager := NewManager("FlowGuard/test")
	t.Cleanup(func() { manager.Close() })
	config := ingestTestConfig()
	if err := manager.UpdateSinks(map[string]map[string]interface{}{"shadow": config}); err != nil {
		t.Fatal(err)
	}

	original := manager.sinks["shadow"].(*FlowGuardIngestSink)
	var generations []string
	var tokens []string
	transport := ingestTestTransport(func(request *http.Request) (*http.Response, error) {
		body := ingestTestBody(t, request)
		var envelope ingestEnvelope
		if err := json.Unmarshal(body, &envelope); err != nil {
			t.Error(err)
		}
		generations = append(generations, envelope.IdentityGeneration)
		tokens = append(tokens, request.Header.Get("Authorization"))

		return ingestTestReceipt(t, request, body), nil
	})
	original.client.Transport = transport
	manager.Write(ingestTestEntry(2031, 6, 8))

	if err := manager.UpdateSinks(map[string]map[string]interface{}{"shadow": config}); err != nil {
		t.Fatal(err)
	}
	if manager.sinks["shadow"] != original {
		t.Fatal("unchanged configuration recreated sink")
	}

	rotated := ingestTestConfig()
	rotated["credential_id"] = strings.Repeat("d", 32)
	if err := manager.UpdateSinks(map[string]map[string]interface{}{"shadow": rotated}); err != nil {
		t.Fatal(err)
	}

	current := manager.sinks["shadow"].(*FlowGuardIngestSink)
	current.client.Transport = transport
	manager.Write(ingestTestEntry(2031, 6, 9))
	if err := manager.UpdateSinks(map[string]map[string]interface{}{}); err != nil {
		t.Fatal(err)
	}

	if !reflect.DeepEqual(generations, []string{strings.Repeat("b", 32), strings.Repeat("d", 32)}) || len(tokens) != 2 || tokens[0] == tokens[1] {
		t.Fatal("reload misattributed pending logs")
	}
	if original.pending != nil || current.pending != nil || manager.HasSinks() {
		t.Fatal("removed sinks retained pending state")
	}
}

func TestFlowGuardIngestFailureDoesNotBlockOpenObserve(t *testing.T) {
	started := make(chan struct{})
	var once sync.Once
	shadow := ingestTestSink(t, func(request *http.Request) (*http.Response, error) {
		once.Do(func() { close(started) })
		<-request.Context().Done()
		return nil, request.Context().Err()
	}, asyncBatchWriterOptions{maxBatchEntries: 1, shutdownTimeout: 10 * time.Millisecond})

	observed := make(chan struct{}, 1)
	created, err := NewOpenObserveSink("primary", map[string]interface{}{
		"url":          "https://observe.example.invalid",
		"organization": "synthetic",
	}, "FlowGuard/test")
	if err != nil {
		t.Fatal(err)
	}
	primary := created.(*OpenObserveSink)
	primary.writer.Close()
	primary.client.Transport = ingestTestTransport(func(*http.Request) (*http.Response, error) {
		observed <- struct{}{}
		return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(`{}`)), Header: make(http.Header)}, nil
	})
	primary.writer = newAsyncBatchWriterWithOptions("openobserve", "primary", primary.sendBatch, asyncBatchWriterOptions{maxBatchEntries: 1})
	t.Cleanup(func() { primary.Close() })

	manager := NewManager("FlowGuard/test")
	manager.sinks = map[string]Sink{"primary": primary, "shadow": shadow}
	t.Cleanup(func() { manager.Close() })
	manager.Write(ingestTestEntry(2031, 6, 8))

	waitIngestSignal(t, started)
	waitIngestSignal(t, observed)
}

func ingestTestConfig() map[string]interface{} {
	return map[string]interface{}{
		"type":             "flowguard_ingest",
		"url":              "https://logs.example.invalid/v1/ingest",
		"protocol_version": 1,
		"credential_id":    strings.Repeat("b", 32),
		"secret":           base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{7}, 32)),
	}
}

func ingestTestEntry(year int, month time.Month, day int) *LogEntry {
	return &LogEntry{Data: map[string]interface{}{
		"_timestamp": time.Date(year, month, day, 12, 0, 0, 0, time.UTC).UnixMicro(),
		"message":    "synthetic event",
	}}
}

type ingestTestTransport func(*http.Request) (*http.Response, error)

func (transport ingestTestTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	return transport(request)
}

func ingestTestSink(t *testing.T, transport ingestTestTransport, options asyncBatchWriterOptions) *FlowGuardIngestSink {
	t.Helper()
	created, err := CreateSink("shadow", ingestTestConfig(), "FlowGuard/test")
	if err != nil {
		t.Fatal(err)
	}

	sink := created.(*FlowGuardIngestSink)
	sink.writer.Close()
	sink.client.Transport = transport
	released := options.onBatchReleased
	options.onBatchReleased = func() {
		sink.releaseBatch()
		if released != nil {
			released()
		}
	}
	sink.writer = newAsyncBatchWriterWithOptions("flowguard_ingest", "shadow", sink.sendBatch, options)
	t.Cleanup(func() { sink.Close() })

	return sink
}

func ingestTestBody(t *testing.T, request *http.Request) []byte {
	t.Helper()
	if request.Header.Get("Content-Encoding") != "gzip" {
		t.Fatal("request was not compressed")
	}

	reader, err := gzip.NewReader(request.Body)
	if err != nil {
		t.Fatal(err)
	}
	defer reader.Close()
	body, err := io.ReadAll(reader)
	if err != nil {
		t.Fatal(err)
	}

	digest := sha256.Sum256(body)
	if request.Header.Get("X-FlowGuard-Batch-SHA256") != hex.EncodeToString(digest[:]) {
		t.Fatal("digest does not match decompressed bytes")
	}

	return body
}

func ingestTestReceipt(t *testing.T, request *http.Request, body []byte) *http.Response {
	t.Helper()
	var envelope ingestEnvelope
	if err := json.Unmarshal(body, &envelope); err != nil {
		t.Fatal(err)
	}

	var rawBytes int
	for _, encoded := range envelope.Events {
		var event ingestEvent
		if err := json.Unmarshal(encoded, &event); err != nil {
			t.Fatal(err)
		}
		rawBytes += len(event.Payload)
	}

	response, err := json.Marshal(map[string]any{
		"protocol_version":      1,
		"state":                 "committed",
		"outcome":               "committed",
		"identity_generation":   envelope.IdentityGeneration,
		"batch_id":              envelope.BatchID,
		"batch_sha256":          request.Header.Get("X-FlowGuard-Batch-SHA256"),
		"request_id":            strings.Repeat("e", 32),
		"code":                  "complete",
		"retryable":             false,
		"event_count":           len(envelope.Events),
		"raw_bytes":             strconv.Itoa(rawBytes),
		"accounting_version":    "flowguard-json-v1",
		"normalization_version": "flowguard-event-v1",
	})
	if err != nil {
		t.Fatal(err)
	}

	return &http.Response{
		StatusCode: http.StatusOK,
		Body:       io.NopCloser(bytes.NewReader(response)),
		Header:     make(http.Header),
	}
}

func waitIngestSignal(t *testing.T, signal <-chan struct{}) {
	t.Helper()
	select {
	case <-signal:
	case <-time.After(3 * time.Second):
		t.Fatal("timed out waiting for sink")
	}
}

func TestFlowGuardIngestShutdownRetriesPendingIdentity(t *testing.T) {
	started := make(chan struct{})
	var bodies [][]byte
	sink := ingestTestSink(t, func(request *http.Request) (*http.Response, error) {
		body := ingestTestBody(t, request)
		bodies = append(bodies, body)
		if len(bodies) == 1 {
			close(started)
			<-request.Context().Done()
			return nil, request.Context().Err()
		}

		return ingestTestReceipt(t, request, body), nil
	}, asyncBatchWriterOptions{maxBatchEntries: 1})

	if err := sink.Write(ingestTestEntry(2031, 6, 8)); err != nil {
		t.Fatal(err)
	}
	waitIngestSignal(t, started)
	if err := sink.Close(); err != nil {
		t.Fatal(err)
	}

	if len(bodies) != 2 || !bytes.Equal(bodies[0], bodies[1]) || sink.pending != nil {
		t.Fatal("shutdown changed pending identity or retained the prepared request")
	}
}

func TestFlowGuardIngestDoesNotForwardCredentialsOnRedirect(t *testing.T) {
	var attempts int
	sink := ingestTestSink(t, func(request *http.Request) (*http.Response, error) {
		attempts++
		return &http.Response{
			StatusCode: http.StatusTemporaryRedirect,
			Header:     http.Header{"Location": {"https://other.example.invalid/v1/ingest"}},
			Body:       io.NopCloser(strings.NewReader("")),
			Request:    request,
		}, nil
	}, asyncBatchWriterOptions{})

	err := sink.sendBatch(context.Background(), []*LogEntry{ingestTestEntry(2031, 6, 8)})
	if err == nil || attempts != 1 {
		t.Fatalf("redirect followed: attempts=%d err=%v", attempts, err)
	}
	sink.releaseBatch()
}
