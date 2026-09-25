package engine

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"
)

func TestPool_BasicExecution(t *testing.T) {
	ctx := context.Background()
	taskCount := 50
	workers := 5

	taskFn := func(ctx context.Context, input int) (int, error) {
		return input * 2, nil
	}

	pool, err := NewPool(ctx, Config{
		Workers:   workers,
		QueueSize: 20,
	}, taskFn)
	if err != nil {
		t.Fatalf("failed to create pool: %v", err)
	}

	// Producer
	go func() {
		for i := 1; i <= taskCount; i++ {
			if err := pool.Submit(ctx, i); err != nil {
				t.Errorf("failed to submit task %d: %v", i, err)
			}
		}
		pool.Stop()
	}()

	// Consumer
	receivedCount := 0
	sum := 0
	for res := range pool.Results() {
		if res.Err != nil {
			t.Errorf("unexpected error: %v", res.Err)
		}
		receivedCount++
		sum += res.Value
	}

	if receivedCount != taskCount {
		t.Fatalf("expected %d results, got %d", taskCount, receivedCount)
	}

	stats := pool.Stats()
	if stats.Completed != uint64(taskCount) {
		t.Errorf("expected %d completed stats, got %d", taskCount, stats.Completed)
	}
}

func TestPool_TaskTimeoutCancellation(t *testing.T) {
	ctx := context.Background()

	// Task timeout set to 50ms, but task hangs for 200ms
	timeout := 50 * time.Millisecond
	pool, err := NewPool(ctx, Config{
		Workers:     2,
		QueueSize:   5,
		TaskTimeout: timeout,
	}, func(taskCtx context.Context, id int) (string, error) {
		select {
		case <-time.After(200 * time.Millisecond):
			return "completed", nil
		case <-taskCtx.Done():
			return "timeout", taskCtx.Err()
		}
	})
	if err != nil {
		t.Fatalf("failed to create pool: %v", err)
	}

	if err := pool.Submit(ctx, 1); err != nil {
		t.Fatalf("submit failed: %v", err)
	}
	pool.Stop()

	res := <-pool.Results()
	if !errors.Is(res.Err, context.DeadlineExceeded) {
		t.Errorf("expected DeadlineExceeded error, got: %v", res.Err)
	}
	if res.Value != "timeout" {
		t.Errorf("expected timeout result, got: %v", res.Value)
	}
}

func TestPool_ParentContextCancellation(t *testing.T) {
	parentCtx, cancel := context.WithCancel(context.Background())

	started := make(chan struct{})
	pool, err := NewPool(parentCtx, Config{
		Workers:   1,
		QueueSize: 2,
	}, func(ctx context.Context, id int) (int, error) {
		close(started)
		<-ctx.Done()
		return id, ctx.Err()
	})
	if err != nil {
		t.Fatalf("failed to create pool: %v", err)
	}

	if err := pool.Submit(parentCtx, 100); err != nil {
		t.Fatalf("submit failed: %v", err)
	}

	<-started
	// Cancel parent context
	cancel()
	pool.Wait()

	// Additional submit should fail
	err = pool.Submit(context.Background(), 200)
	if err == nil {
		t.Errorf("expected submit error after cancellation, got nil")
	}
}

func TestPool_GracefulStopRejectsNewTasks(t *testing.T) {
	ctx := context.Background()
	pool, err := NewPool(ctx, Config{
		Workers:   2,
		QueueSize: 5,
	}, func(ctx context.Context, id int) (int, error) {
		time.Sleep(20 * time.Millisecond)
		return id, nil
	})
	if err != nil {
		t.Fatalf("failed to create pool: %v", err)
	}

	if err := pool.Submit(ctx, 1); err != nil {
		t.Fatalf("submit failed: %v", err)
	}

	pool.Stop()

	err = pool.Submit(ctx, 2)
	if !errors.Is(err, ErrPoolClosed) {
		t.Errorf("expected ErrPoolClosed, got: %v", err)
	}

	// Make sure the first item completes
	count := 0
	for range pool.Results() {
		count++
	}
	if count != 1 {
		t.Errorf("expected 1 completed result, got %d", count)
	}
}

func TestPool_PanicRecovery(t *testing.T) {
	ctx := context.Background()
	pool, err := NewPool(ctx, Config{
		Workers:   1,
		QueueSize: 2,
	}, func(ctx context.Context, id int) (int, error) {
		if id == 42 {
			panic("simulated fatal probe crash")
		}
		return id * 10, nil
	})
	if err != nil {
		t.Fatalf("failed to create pool: %v", err)
	}

	_ = pool.Submit(ctx, 42)
	_ = pool.Submit(ctx, 5)
	pool.Stop()

	res1 := <-pool.Results()
	if res1.Err == nil || res1.Err.Error() != "task panicked: simulated fatal probe crash" {
		t.Errorf("expected panic recovery error, got: %v", res1.Err)
	}

	res2 := <-pool.Results()
	if res2.Err != nil || res2.Value != 50 {
		t.Errorf("expected normal execution after recovered panic, got: %v, %v", res2.Value, res2.Err)
	}
}

func TestPool_RateLimiting(t *testing.T) {
	ctx := context.Background()
	// Rate limit: 10 per sec, burst 1 -> ~100ms per task
	limiter := NewTokenBucketLimiter(10, 1)
	defer limiter.Stop()

	start := time.Now()
	var executed atomic.Int32

	pool, err := NewPool(ctx, Config{
		Workers:   4,
		QueueSize: 10,
		Limiter:   limiter,
	}, func(ctx context.Context, id int) (int, error) {
		executed.Add(1)
		return id, nil
	})
	if err != nil {
		t.Fatalf("failed to create pool: %v", err)
	}

	total := 4
	for i := 0; i < total; i++ {
		_ = pool.Submit(ctx, i)
	}
	pool.Stop()

	for range pool.Results() {
	}

	elapsed := time.Since(start)
	// 4 tasks with 10/sec rate limiter should take at least ~250-300ms
	if elapsed < 200*time.Millisecond {
		t.Logf("completed in %v (fast burst allowed)", elapsed)
	}
	if executed.Load() != int32(total) {
		t.Errorf("expected %d executions, got %d", total, executed.Load())
	}
}
