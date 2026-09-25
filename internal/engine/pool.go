package engine

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"time"
)

var (
	// ErrPoolClosed is returned when attempting to submit work to a closed worker pool.
	ErrPoolClosed = errors.New("worker pool is closed")
	// ErrPoolQueueFull is returned when non-blocking submission fails because the task queue is at capacity.
	ErrPoolQueueFull = errors.New("worker pool task queue is full")
	// ErrNilTaskFunc is returned if an empty execution function is supplied.
	ErrNilTaskFunc = errors.New("task function cannot be nil")
)

// TaskFunc defines the execution signature for a worker unit.
// It accepts a context (with cancellation/timeout propagation) and an input payload of type T,
// returning an output of type R or an error.
type TaskFunc[T any, R any] func(ctx context.Context, input T) (R, error)

// Result encapsulates the outcome of a processed task.
type Result[R any] struct {
	Value R
	Err   error
}

// Config specifies runtime options for the worker pool.
type Config struct {
	// Workers determines the number of concurrent worker goroutines.
	Workers int
	// QueueSize sets the buffer size for inbound task queue.
	QueueSize int
	// TaskTimeout sets an optional per-task execution timeout. 0 means inherit parent context.
	TaskTimeout time.Duration
	// Limiter provides an optional rate limiter to throttle task execution.
	Limiter RateLimiter
}

// Stats provides thread-safe runtime metrics for monitoring and telemetry.
type Stats struct {
	Submitted uint64
	Completed uint64
	Failed    uint64
	Active    int64
}

// Pool manages a bounded set of concurrent workers executing generic tasks.
type Pool[T any, R any] struct {
	cfg      Config
	taskFn   TaskFunc[T, R]
	taskCh   chan T
	resultCh chan Result[R]

	// Context lifecycle
	ctx    context.Context
	cancel context.CancelFunc

	// Synchronization
	workerWg sync.WaitGroup
	submitWg sync.WaitGroup
	submitMu sync.RWMutex
	stopOnce sync.Once
	doneOnce sync.Once

	// State and metrics
	isClosed  atomic.Bool
	submitted atomic.Uint64
	completed atomic.Uint64
	failed    atomic.Uint64
	active    atomic.Int64
}

// NewPool initializes and starts a new generic worker pool with the given context and configuration.
func NewPool[T any, R any](parentCtx context.Context, cfg Config, taskFn TaskFunc[T, R]) (*Pool[T, R], error) {
	if taskFn == nil {
		return nil, ErrNilTaskFunc
	}
	if cfg.Workers <= 0 {
		cfg.Workers = 1
	}
	if cfg.QueueSize < 0 {
		cfg.QueueSize = 0
	}

	ctx, cancel := context.WithCancel(parentCtx)

	p := &Pool[T, R]{
		cfg:      cfg,
		taskFn:   taskFn,
		taskCh:   make(chan T, cfg.QueueSize),
		resultCh: make(chan Result[R], cfg.QueueSize),
		ctx:      ctx,
		cancel:   cancel,
	}

	// Spawn workers
	p.workerWg.Add(cfg.Workers)
	for i := 0; i < cfg.Workers; i++ {
		go p.worker(i)
	}

	// Coordinator goroutine: closes resultCh after all workers finish
	go func() {
		p.workerWg.Wait()
		p.doneOnce.Do(func() {
			close(p.resultCh)
		})
	}()

	return p, nil
}

// Submit submits a task to the pool. It blocks until the task can be queued,
// or until either the call context or the pool context is cancelled.
func (p *Pool[T, R]) Submit(ctx context.Context, item T) error {
	if err := p.ctx.Err(); err != nil {
		return err
	}
	if err := ctx.Err(); err != nil {
		return err
	}

	p.submitMu.RLock()
	if p.isClosed.Load() {
		p.submitMu.RUnlock()
		return ErrPoolClosed
	}
	p.submitWg.Add(1)
	p.submitMu.RUnlock()
	defer p.submitWg.Done()

	select {
	case <-p.ctx.Done():
		return p.ctx.Err()
	case <-ctx.Done():
		return ctx.Err()
	case p.taskCh <- item:
		p.submitted.Add(1)
		return nil
	}
}

// TrySubmit attempts to submit a task without blocking. If the queue is full or closed,
// it returns an error immediately.
func (p *Pool[T, R]) TrySubmit(item T) error {
	if err := p.ctx.Err(); err != nil {
		return err
	}

	p.submitMu.RLock()
	if p.isClosed.Load() {
		p.submitMu.RUnlock()
		return ErrPoolClosed
	}
	p.submitWg.Add(1)
	p.submitMu.RUnlock()
	defer p.submitWg.Done()

	select {
	case <-p.ctx.Done():
		return p.ctx.Err()
	case p.taskCh <- item:
		p.submitted.Add(1)
		return nil
	default:
		return ErrPoolQueueFull
	}
}

// Feed continuously reads tasks from an upstream channel and submits them into the pool.
// It stops when upstream is closed or when context cancels.
func (p *Pool[T, R]) Feed(ctx context.Context, stream <-chan T) error {
	for {
		select {
		case item, ok := <-stream:
			if !ok {
				return nil
			}
			if err := p.Submit(ctx, item); err != nil {
				return err
			}
		case <-ctx.Done():
			return ctx.Err()
		case <-p.ctx.Done():
			return p.ctx.Err()
		}
	}
}

// Results returns a read-only channel for consuming results as tasks finish.
// The channel is closed once all workers complete their execution.
func (p *Pool[T, R]) Results() <-chan Result[R] {
	return p.resultCh
}

// worker is the core event loop executed by each worker goroutine.
func (p *Pool[T, R]) worker(workerID int) {
	defer p.workerWg.Done()

	for {
		select {
		case <-p.ctx.Done():
			return
		case item, ok := <-p.taskCh:
			if !ok {
				// Queue has been closed and drained
				return
			}

			// Apply rate limiter if configured
			if p.cfg.Limiter != nil {
				if err := p.cfg.Limiter.Wait(p.ctx); err != nil {
					// Pool context cancelled during rate limit wait
					return
				}
			}

			p.processTask(item)
		}
	}
}

// processTask handles the execution of a single task with context propagation and panic safety.
func (p *Pool[T, R]) processTask(item T) {
	p.active.Add(1)
	defer p.active.Add(-1)

	// Establish execution context (with optional per-task timeout)
	var taskCtx context.Context
	var cancel context.CancelFunc

	if p.cfg.TaskTimeout > 0 {
		taskCtx, cancel = context.WithTimeout(p.ctx, p.cfg.TaskTimeout)
	} else {
		taskCtx, cancel = context.WithCancel(p.ctx)
	}
	defer cancel()

	var res R
	var err error

	// Execute with panic recovery to prevent a single faulty probe/task from crashing the runtime
	func() {
		defer func() {
			if r := recover(); r != nil {
				err = fmt.Errorf("task panicked: %v", r)
			}
		}()
		res, err = p.taskFn(taskCtx, item)
	}()

	if err != nil {
		p.failed.Add(1)
	} else {
		p.completed.Add(1)
	}

	result := Result[R]{
		Value: res,
		Err:   err,
	}

	// Dispatch result or abort if pool context has terminated
	select {
	case p.resultCh <- result:
	case <-p.ctx.Done():
	}
}

// Stop initiates a graceful shutdown: stops accepting new submissions,
// allows queued tasks to finish processing, and closes the results channel once done.
func (p *Pool[T, R]) Stop() {
	p.stopOnce.Do(func() {
		p.submitMu.Lock()
		p.isClosed.Store(true)
		p.submitMu.Unlock()

		// Wait for in-flight Submit calls to complete their channel sends
		p.submitWg.Wait()

		// Close the task channel to signal workers that no more items will arrive
		close(p.taskCh)
	})
}

// Wait blocks until all workers have finished processing all queued tasks and exited.
func (p *Pool[T, R]) Wait() {
	p.workerWg.Wait()
}

// Cancel immediately halts the pool, cancelling in-flight tasks and exiting workers.
func (p *Pool[T, R]) Cancel() {
	p.cancel()
	p.Stop()
}

// Stats returns a snapshot of the current pool operational metrics.
func (p *Pool[T, R]) Stats() Stats {
	return Stats{
		Submitted: p.submitted.Load(),
		Completed: p.completed.Load(),
		Failed:    p.failed.Load(),
		Active:    p.active.Load(),
	}
}
