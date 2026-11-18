package contribution

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"
)

const maxSweepPagesPerCycle = 100

type WorkerConfig struct {
	ID             string
	Concurrency    int
	PollInterval   time.Duration
	MaxIdleBackoff time.Duration
	SweepInterval  time.Duration
	SweepBatchSize int
	ShutdownBudget time.Duration
}
type WorkerSnapshot struct {
	Running     bool
	Active      int
	Completed   uint64
	Failed      uint64
	Sweeps      uint64
	SweepCursor string
	LastSweepAt time.Time
	LastError   string
}

// Worker runs bounded RunOne loops and paginated Sweep passes with graceful shutdown.
type Worker struct {
	service *Service
	cfg     WorkerConfig
	mu      sync.Mutex
	state   WorkerSnapshot
	started bool
	stop    chan struct{}
	done    chan struct{}
	cancel  context.CancelFunc
}

func NewWorker(s *Service, cfg WorkerConfig) (*Worker, error) {
	if cfg.Concurrency == 0 {
		cfg.Concurrency = 1
	}
	if cfg.PollInterval == 0 {
		cfg.PollInterval = time.Second
	}
	if cfg.MaxIdleBackoff == 0 {
		cfg.MaxIdleBackoff = max(15*time.Second, cfg.PollInterval)
	}
	if cfg.SweepInterval == 0 {
		cfg.SweepInterval = 15 * time.Second
	}
	if cfg.SweepBatchSize == 0 {
		cfg.SweepBatchSize = 50
	}
	if cfg.ShutdownBudget == 0 {
		cfg.ShutdownBudget = 15 * time.Second
	}
	if s == nil || !identifier.MatchString(cfg.ID) || len(cfg.ID) > 100 || cfg.Concurrency < 1 || cfg.Concurrency > 16 || cfg.PollInterval < 10*time.Millisecond || cfg.PollInterval > time.Minute || cfg.MaxIdleBackoff < cfg.PollInterval || cfg.MaxIdleBackoff > time.Minute || cfg.SweepInterval < 50*time.Millisecond || cfg.SweepInterval > time.Hour || cfg.SweepBatchSize < 1 || cfg.SweepBatchSize > 100 || cfg.ShutdownBudget < 100*time.Millisecond || cfg.ShutdownBudget > time.Minute {
		return nil, ErrInput
	}
	return &Worker{
		service: s,
		cfg:     cfg,
		stop:    make(chan struct{}),
		done:    make(chan struct{}),
	}, nil
}
func (w *Worker) Start(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := w.service.authorize(ctx, w.service.cfg.Actor, "contributions.maintenance", Record{}); err != nil {
		return err
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.started {
		return ErrConflict
	}
	w.started = true
	w.state.Running = true
	work, cancel := context.WithCancel(context.Background())
	w.cancel = cancel
	var wg sync.WaitGroup
	for i := 0; i < w.cfg.Concurrency; i++ {
		wg.Add(1)
		workerID := fmt.Sprintf("%s-%d", w.cfg.ID, i)
		go func() {
			defer wg.Done()
			w.runLoop(work, workerID)
		}()
	}
	wg.Add(1)
	go func() {
		defer wg.Done()
		w.sweepLoop(work)
	}()
	go func() {
		wg.Wait()
		cancel()
		w.mu.Lock()
		w.state.Running = false
		w.mu.Unlock()
		close(w.done)
	}()
	return nil
}
func (w *Worker) Snapshot() WorkerSnapshot {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.state
}
func (w *Worker) Done() <-chan struct{} { return w.done }
func (w *Worker) stopping() bool {
	select {
	case <-w.stop:
		return true
	default:
		return false
	}
}
func (w *Worker) sleep(ctx context.Context, d time.Duration) bool {
	timer := time.NewTimer(d)
	defer timer.Stop()
	select {
	case <-timer.C:
		return !w.stopping()
	case <-w.stop:
		return false
	case <-ctx.Done():
		return false
	}
}
func (w *Worker) runLoop(ctx context.Context, workerID string) {
	backoff := w.cfg.PollInterval
	for !w.stopping() {
		w.mu.Lock()
		if w.stopping() {
			w.mu.Unlock()
			return
		}
		w.state.Active++
		w.mu.Unlock()

		err := w.service.RunOne(ctx, workerID)
		idle := errors.Is(err, ErrNotFound)

		w.mu.Lock()
		w.state.Active--
		switch {
		case err == nil:
			w.state.Completed++
		case !idle:
			w.state.Failed++
			w.state.LastError = workerErrorCode(err)
		}
		w.mu.Unlock()

		if err == nil {
			backoff = w.cfg.PollInterval
			continue
		}
		if !w.sleep(ctx, backoff) {
			return
		}
		backoff = min(w.cfg.MaxIdleBackoff, backoff*2)
	}
}
func (w *Worker) sweepLoop(ctx context.Context) {
	cursor := ""
	for !w.stopping() {
		var sweepErr error
		for page := 0; page < maxSweepPagesPerCycle && !w.stopping() && ctx.Err() == nil; page++ {
			next, err := w.service.Sweep(ctx, w.cfg.SweepBatchSize, cursor)
			if err != nil {
				sweepErr = err
				break
			}
			cursor = next
			if cursor == "" {
				break
			}
		}
		w.mu.Lock()
		w.state.SweepCursor = cursor
		if sweepErr == nil {
			w.state.Sweeps++
			w.state.LastSweepAt = w.service.now()
		} else if !w.stopping() {
			w.state.LastError = workerErrorCode(sweepErr)
		}
		w.mu.Unlock()
		if !w.sleep(ctx, w.cfg.SweepInterval) {
			return
		}
	}
}

// Stop stops claiming new work and waits up to the minimum of ctx and ShutdownBudget
// (default 15s) before canceling in-flight operations, leaving leases for recovery.
func (w *Worker) Stop(ctx context.Context) error {
	w.mu.Lock()
	if !w.started {
		w.mu.Unlock()
		return nil
	}
	if !w.stopping() {
		close(w.stop)
	}
	w.mu.Unlock()

	budgetCtx, cancelBudget := context.WithTimeout(ctx, w.cfg.ShutdownBudget)
	defer cancelBudget()
	select {
	case <-w.done:
		return nil
	case <-budgetCtx.Done():
		w.cancel()
		if ctx.Err() != nil {
			return ctx.Err()
		}
		select {
		case <-w.done:
			return context.DeadlineExceeded
		case <-ctx.Done():
			return ctx.Err()
		}
	}
}
func workerErrorCode(err error) string {
	switch {
	case errors.Is(err, ErrDenied):
		return "permission_denied"
	case errors.Is(err, ErrConflict):
		return "conflict"
	case errors.Is(err, context.Canceled):
		return "canceled"
	case errors.Is(err, context.DeadlineExceeded):
		return "deadline_exceeded"
	default:
		return "unavailable"
	}
}
