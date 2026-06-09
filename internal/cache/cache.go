// Package cache provides a tiny in-memory TTL cache for scan reports so that
// repeated scans of the same domain (with the same options) return identical,
// fast results instead of re-querying flaky third-party sources every time.
package cache

import (
	"sync"
	"time"

	"github.com/rahuljoshi/subscope/internal/model"
)

type entry struct {
	report   *model.Report
	discover *model.DiscoverResult
	expires  time.Time
}

// Cache is a concurrency-safe TTL cache of scan reports and discovery results.
type Cache struct {
	mu  sync.Mutex
	m   map[string]entry
	ttl time.Duration
}

// New creates a cache with the given TTL. A ttl <= 0 disables caching (Get
// always misses, Set is a no-op).
func New(ttl time.Duration) *Cache {
	c := &Cache{m: make(map[string]entry), ttl: ttl}
	if ttl > 0 {
		go c.gc()
	}
	return c
}

// GetDiscover returns a cached discovery result (a copy) if present/unexpired.
func (c *Cache) GetDiscover(key string) (*model.DiscoverResult, bool) {
	if c.ttl <= 0 {
		return nil, false
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	e, ok := c.m[key]
	if !ok || e.discover == nil || time.Now().After(e.expires) {
		return nil, false
	}
	cp := *e.discover
	cp.Cached = true
	return &cp, true
}

// SetDiscover stores a discovery result under key.
func (c *Cache) SetDiscover(key string, res *model.DiscoverResult) {
	if c.ttl <= 0 || res == nil {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.m[key] = entry{discover: res, expires: time.Now().Add(c.ttl)}
}

// Get returns a cached report (a copy) if present and unexpired.
func (c *Cache) Get(key string) (*model.Report, bool) {
	if c.ttl <= 0 {
		return nil, false
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	e, ok := c.m[key]
	if !ok || time.Now().After(e.expires) {
		return nil, false
	}
	cp := *e.report
	cp.Cached = true
	return &cp, true
}

// Set stores a report under key.
func (c *Cache) Set(key string, report *model.Report) {
	if c.ttl <= 0 || report == nil {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.m[key] = entry{report: report, expires: time.Now().Add(c.ttl)}
}

func (c *Cache) gc() {
	t := time.NewTicker(c.ttl)
	for range t.C {
		c.mu.Lock()
		now := time.Now()
		for k, e := range c.m {
			if now.After(e.expires) {
				delete(c.m, k)
			}
		}
		c.mu.Unlock()
	}
}
