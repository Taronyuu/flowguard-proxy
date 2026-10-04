package decisions

import (
	"bufio"
	"bytes"
	"encoding/json"
	"log"
	"net"
	"runtime"
	"sync"
	"time"
)

const maxLineBytes = 4096

var sweepInterval = time.Minute

type SubscriberConfig struct {
	SocketPath string
	ScorerUID  int
	MaxEntries int
}

type Subscriber struct {
	store *Store

	mu      sync.Mutex
	cfg     SubscriberConfig
	verbose bool
	running bool
	stopCh  chan struct{}
	wg      sync.WaitGroup
}

func NewSubscriber(store *Store) *Subscriber {
	return &Subscriber{store: store}
}

func (s *Subscriber) Start(cfg SubscriberConfig, verbose bool) {
	s.mu.Lock()
	if s.running && s.cfg == cfg {
		s.mu.Unlock()
		return
	}
	wasRunning := s.running
	s.mu.Unlock()

	if wasRunning {
		s.Stop()
	}

	s.store.SetMaxEntries(cfg.MaxEntries)

	s.mu.Lock()
	s.cfg = cfg
	s.verbose = verbose
	s.stopCh = make(chan struct{})
	stopCh := s.stopCh
	s.running = true
	s.mu.Unlock()

	s.wg.Add(2)
	go s.run(stopCh)
	go s.sweep(stopCh)
}

func (s *Subscriber) sweep(stopCh chan struct{}) {
	defer s.wg.Done()
	ticker := time.NewTicker(sweepInterval)
	defer ticker.Stop()
	for {
		select {
		case <-stopCh:
			return
		case now := <-ticker.C:
			s.store.Sweep(now)
		}
	}
}

func (s *Subscriber) Stop() {
	s.mu.Lock()
	if !s.running {
		s.mu.Unlock()
		return
	}
	close(s.stopCh)
	s.running = false
	s.mu.Unlock()

	s.wg.Wait()
	s.store.Clear()
}

func (s *Subscriber) config() SubscriberConfig {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.cfg
}

func (s *Subscriber) isVerbose() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.verbose
}

func (s *Subscriber) run(stopCh chan struct{}) {
	defer s.wg.Done()

	delay := time.Second
	const maxDelay = 30 * time.Second

	for {
		select {
		case <-stopCh:
			return
		default:
		}

		cfg := s.config()
		conn, err := net.Dial("unix", cfg.SocketPath)
		if err != nil {
			if s.isVerbose() {
				log.Printf("[decisions] connect to %s failed: %v", cfg.SocketPath, err)
			}
			if !sleepOrStop(stopCh, delay) {
				return
			}
			delay = nextBackoff(delay, maxDelay)
			continue
		}

		if err := checkPeerUID(conn, cfg.ScorerUID); err != nil {
			log.Printf("[decisions] refusing scorer connection on %s: %v", cfg.SocketPath, err)
			conn.Close()
			if !sleepOrStop(stopCh, delay) {
				return
			}
			delay = nextBackoff(delay, maxDelay)
			continue
		}

		delay = time.Second
		log.Printf("[decisions] connected to scorer at %s", cfg.SocketPath)
		err = s.handleConnection(conn, stopCh)
		conn.Close()
		if err != nil && s.isVerbose() {
			log.Printf("[decisions] connection to %s closed: %v", cfg.SocketPath, err)
		}

		select {
		case <-stopCh:
			return
		default:
		}
	}
}

func nextBackoff(d, max time.Duration) time.Duration {
	d *= 2
	if d > max {
		return max
	}
	return d
}

func sleepOrStop(stopCh <-chan struct{}, d time.Duration) bool {
	timer := time.NewTimer(d)
	defer timer.Stop()
	select {
	case <-stopCh:
		return false
	case <-timer.C:
		return true
	}
}

type syncState struct {
	active bool
	staged map[string]Decision
}

func (s *Subscriber) handleConnection(conn net.Conn, stopCh <-chan struct{}) error {
	closed := make(chan struct{})
	go func() {
		select {
		case <-stopCh:
			conn.Close()
		case <-closed:
		}
	}()
	defer close(closed)

	reader := bufio.NewReaderSize(conn, maxLineBytes)
	st := &syncState{}
	msg := &wireMessage{Decision: &wireDecision{}}
	const yieldEvery = 256
	linesSinceYield := 0

	for {
		linesSinceYield++
		if linesSinceYield >= yieldEvery {
			linesSinceYield = 0
			runtime.Gosched()
		}

		line, err := reader.ReadSlice('\n')
		if err == bufio.ErrBufferFull {
			for err == bufio.ErrBufferFull {
				_, err = reader.ReadSlice('\n')
			}
			if err != nil {
				return err
			}
			log.Printf("[decisions] oversized line skipped")
			continue
		}
		if err != nil {
			return err
		}

		trimmed := bytes.TrimRight(line, "\n")
		if len(trimmed) == 0 {
			continue
		}

		s.handleLine(trimmed, st, msg)
	}
}

func (s *Subscriber) handleLine(line []byte, st *syncState, msg *wireMessage) {
	msg.Type = ""
	msg.Key = ""
	*msg.Decision = wireDecision{}
	if err := json.Unmarshal(line, msg); err != nil {
		log.Printf("[decisions] malformed message skipped: %v", err)
		return
	}

	switch msg.Type {
	case "sync_begin":
		st.active = true
		st.staged = make(map[string]Decision)

	case "put":
		d, err := decodeDecision(msg.Decision, time.Now())
		if err != nil {
			log.Printf("[decisions] skipping decision: %v", err)
			return
		}
		if st.active {
			st.staged[d.Key] = d
		} else {
			s.store.Put(d)
		}

	case "del":
		if !validKeyForm(msg.Key) {
			log.Printf("[decisions] skipping del: invalid key form %q", msg.Key)
			return
		}
		if st.active {
			delete(st.staged, msg.Key)
		} else {
			s.store.Delete(msg.Key)
		}

	case "sync_end":
		if !st.active {
			log.Printf("[decisions] sync_end received without a sync_begin, ignoring")
			return
		}
		s.store.ReplaceAll(st.staged)
		st.active = false
		st.staged = nil

	default:
		log.Printf("[decisions] unknown message type %q skipped", msg.Type)
	}
}
