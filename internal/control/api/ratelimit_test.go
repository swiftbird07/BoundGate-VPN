package api

import (
	"strconv"
	"testing"
	"time"
)

// A flood of fresh addresses must not grow the limiter without bound: a
// client it has not seen is refused beyond the cap, clients it knows keep
// their buckets.
func TestRateLimiterStaysBounded(t *testing.T) {
	l := newRateLimiter(2, time.Hour)
	if !l.allow("known") {
		t.Fatal("the first request of a client was refused")
	}
	for i := 0; i < maxBuckets+100; i++ {
		l.allow(strconv.Itoa(i))
	}
	if len(l.buckets) > maxBuckets {
		t.Fatalf("%d buckets, cap %d", len(l.buckets), maxBuckets)
	}
	if l.allow("stranger") {
		t.Error("a client beyond the cap was given a bucket")
	}
	if !l.allow("known") {
		t.Error("a known client was refused under the flood")
	}
}
