/*
Package http provides a high-performance HTTP client for ANANKE.
Uses fasthttp for maximum throughput.
*/
package http

import (
	"crypto/tls"
	"fmt"
	"time"

	"github.com/valyala/fasthttp"
)

// Client wraps fasthttp for ANANKE operations
type Client struct {
	client     *fasthttp.Client
	authHeader string
	cookie     string
	timeout    time.Duration
	userAgent  string
}

// Response holds the HTTP response data
type Response struct {
	StatusCode int
	Body       []byte
	Headers    map[string]string
	Duration   time.Duration
}

// NewClient creates a new HTTP client
func NewClient(opts ...Option) *Client {
	c := &Client{
		timeout:   10 * time.Second,
		userAgent: "ANANKE/0.1.0",
	}

	// Apply options
	for _, opt := range opts {
		opt(c)
	}

	// Configure fasthttp client
	c.client = &fasthttp.Client{
		ReadTimeout:         c.timeout,
		WriteTimeout:        c.timeout,
		MaxConnsPerHost:     1000,
		MaxIdleConnDuration: 30 * time.Second,
		TLSConfig: &tls.Config{
			InsecureSkipVerify: true,
		},
	}

	return c
}

// Option configures the client
type Option func(*Client)

// WithAuth sets the Authorization header
func WithAuth(auth string) Option {
	return func(c *Client) {
		c.authHeader = auth
	}
}

// WithCookie sets cookies
func WithCookie(cookie string) Option {
	return func(c *Client) {
		c.cookie = cookie
	}
}

// WithTimeout sets the request timeout
func WithTimeout(d time.Duration) Option {
	return func(c *Client) {
		c.timeout = d
	}
}

// WithUserAgent sets custom user agent
func WithUserAgent(ua string) Option {
	return func(c *Client) {
		c.userAgent = ua
	}
}

// Get performs a GET request
func (c *Client) Get(url string) (*Response, error) {
	return c.do("GET", url, nil)
}

// Post performs a POST request
func (c *Client) Post(url string, body []byte) (*Response, error) {
	return c.do("POST", url, body)
}

// Do performs a custom request
func (c *Client) do(method, url string, body []byte) (*Response, error) {
	req := fasthttp.AcquireRequest()
	resp := fasthttp.AcquireResponse()
	defer fasthttp.ReleaseRequest(req)
	defer fasthttp.ReleaseResponse(resp)

	// Setup request
	req.SetRequestURI(url)
	req.Header.SetMethod(method)
	req.Header.Set("User-Agent", c.userAgent)

	// Auth header
	if c.authHeader != "" {
		req.Header.Set("Authorization", c.authHeader)
	}

	// Cookie
	if c.cookie != "" {
		req.Header.Set("Cookie", c.cookie)
	}

	// Body
	if body != nil {
		req.SetBody(body)
		req.Header.Set("Content-Type", "application/json")
	}

	// Execute
	start := time.Now()
	err := c.client.Do(req, resp)
	duration := time.Since(start)

	if err != nil {
		return nil, fmt.Errorf("request failed: %w", err)
	}

	// Build response
	headers := make(map[string]string)
	resp.Header.VisitAll(func(key, value []byte) {
		headers[string(key)] = string(value)
	})

	return &Response{
		StatusCode: resp.StatusCode(),
		Body:       append([]byte{}, resp.Body()...), // Copy body
		Headers:    headers,
		Duration:   duration,
	}, nil
}

// DoParallel executes multiple requests in parallel
func (c *Client) DoParallel(urls []string, workers int) []*Response {
	results := make([]*Response, len(urls))
	jobs := make(chan int, len(urls))
	done := make(chan bool, workers)

	// Start workers
	for w := 0; w < workers; w++ {
		go func() {
			for i := range jobs {
				resp, err := c.Get(urls[i])
				if err == nil {
					results[i] = resp
				}
			}
			done <- true
		}()
	}

	// Send jobs
	for i := range urls {
		jobs <- i
	}
	close(jobs)

	// Wait for workers
	for w := 0; w < workers; w++ {
		<-done
	}

	return results
}
