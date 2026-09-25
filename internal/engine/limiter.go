package engine

import (
	"context"
	"errors"
	"sync"
	"time"
)

var (
	// ErrRateLimitCancelled indicates that the rate limiter wait was aborted due to context cancellation.
	ErrRateLimitCancelled = errors.New("rate limiter wait cancelled by context")
)

// RateLimiter defines the contract for controlling execution rates across workers.
type RateLimiter interface {
	// Wait blocks until an execution slot is available or the context is cancelled.
	Wait(ctx context.Context) error
}

// TokenBucketLimiter implements a classic token bucket algorithm using Go channels and a ticker.
type TokenBucketLimiter struct {
	tokens chan struct{}
	ticker *time.Ticker
	stopCh chan struct{}
	once   sync.Once
}

// NewTokenBucketLimiter creates a thread-safe token bucket rate limiter.
// ratePerSec defines how many tokens are replenished per second.
// burst defines the maximum burst capacity.
func NewTokenBucketLimiter(ratePerSec int, burst int) *TokenBucketLimiter {
	if ratePerSec <= 0 {
		ratePerSec = 1
	}
	if burst <= 0 {
		burst = 1
	}

	tb := &TokenBucketLimiter{
		tokens: make(chan struct{}, burst),
		stopCh: make(chan struct{}),
	}

	// Pre-fill bucket with initial burst capacity
	for i := 0; i < burst; i++ {
		tb.tokens <- struct{}{}
	}

	interval := time.Second / time.Duration(ratePerSec)
	tb.ticker = time.NewTicker(interval)

	go func() {
		for {
			select {
			case <-tb.ticker.C:
				select {
				case tb.tokens <- struct{}{}:
				default:
					// Bucket is full, drop extra token
				}
			case <-tb.stopCh:
				return
			}
		}
	}()

	return tb
}

// Wait acquires a token from the bucket, or blocks until available or ctx is cancelled.
func (tb *TokenBucketLimiter) Wait(ctx context.Context) error {
	select {
	case <-tb.tokens:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// Stop shuts down the replenishment ticker.
func (tb *TokenBucketLimiter) Stop() {
	tb.once.Do(func() {
		tb.ticker.Stop()
		close(tb.stopCh)
	})
}
