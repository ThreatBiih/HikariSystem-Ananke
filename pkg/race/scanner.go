/*
Package race provides race condition vulnerability detection.
Uses goroutines for precise timing attacks.
*/
package race

import (
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	"github.com/fatih/color"
	"github.com/hikarisystem/ananke/pkg/http"
)

// Scanner performs race condition testing
type Scanner struct {
	client   *http.Client
	threads  int
	delay    time.Duration
	verbose  bool
}

// Result holds race condition test results
type Result struct {
	TotalRequests    int
	SuccessCount     int32
	UniqueResponses  int
	ResponseCodes    map[int]int
	TimingStats      TimingStats
	PotentialRace    bool
	Evidence         string
}

// TimingStats holds timing information
type TimingStats struct {
	MinDuration time.Duration
	MaxDuration time.Duration
	AvgDuration time.Duration
}

// Config holds scanner configuration
type Config struct {
	URL        string
	Method     string
	Body       []byte
	Threads    int
	Delay      time.Duration
	AuthHeader string
	Cookie     string
	Verbose    bool
}

// NewScanner creates a new race condition scanner
func NewScanner(cfg *Config) *Scanner {
	opts := []http.Option{
		http.WithTimeout(30 * time.Second),
	}

	if cfg.AuthHeader != "" {
		opts = append(opts, http.WithAuth(cfg.AuthHeader))
	}
	if cfg.Cookie != "" {
		opts = append(opts, http.WithCookie(cfg.Cookie))
	}

	return &Scanner{
		client:  http.NewClient(opts...),
		threads: cfg.Threads,
		delay:   cfg.Delay,
		verbose: cfg.Verbose,
	}
}

// Scan performs the race condition test
func (s *Scanner) Scan(cfg *Config) (*Result, error) {
	color.Yellow("[*] Starting Race Condition scan...")
	color.White("    Threads: %d", cfg.Threads)
	color.White("    Delay: %v", cfg.Delay)
	fmt.Println()

	result := &Result{
		TotalRequests: cfg.Threads,
		ResponseCodes: make(map[int]int),
	}

	// Collect all responses
	responses := make([]*http.Response, cfg.Threads)
	durations := make([]time.Duration, cfg.Threads)
	var successCount int32
	var mu sync.Mutex

	// Barrier for synchronized start
	var ready sync.WaitGroup
	ready.Add(cfg.Threads)
	
	var start sync.WaitGroup
	start.Add(1)

	var done sync.WaitGroup
	done.Add(cfg.Threads)

	// Launch all goroutines
	for i := 0; i < cfg.Threads; i++ {
		go func(idx int) {
			defer done.Done()
			
			// Signal ready
			ready.Done()
			
			// Wait for synchronized start
			start.Wait()

			// Optional micro-delay for staggering
			if s.delay > 0 && idx > 0 {
				time.Sleep(s.delay * time.Duration(idx))
			}

			// Execute request
			var resp *http.Response
			var err error

			startTime := time.Now()
			if cfg.Method == "POST" {
				resp, err = s.client.Post(cfg.URL, cfg.Body)
			} else {
				resp, err = s.client.Get(cfg.URL)
			}
			duration := time.Since(startTime)

			if err == nil && resp != nil {
				mu.Lock()
				responses[idx] = resp
				durations[idx] = duration
				result.ResponseCodes[resp.StatusCode]++
				mu.Unlock()

				if resp.StatusCode >= 200 && resp.StatusCode < 300 {
					atomic.AddInt32(&successCount, 1)
				}
			}
		}(i)
	}

	// Wait for all goroutines to be ready
	ready.Wait()

	// Synchronized start!
	color.Cyan("[*] All %d goroutines ready. FIRING!", cfg.Threads)
	startTime := time.Now()
	start.Done()

	// Wait for completion
	done.Wait()
	totalTime := time.Since(startTime)

	result.SuccessCount = successCount

	// Analyze responses
	s.analyzeResponses(responses, durations, result)

	// Print results
	s.printResults(result, totalTime)

	return result, nil
}

// analyzeResponses checks for race condition indicators
func (s *Scanner) analyzeResponses(responses []*http.Response, durations []time.Duration, result *Result) {
	// Find unique responses
	uniqueBodies := make(map[string]int)
	var minDur, maxDur time.Duration
	var totalDur time.Duration
	var validCount int

	for i, resp := range responses {
		if resp == nil {
			continue
		}

		validCount++
		bodyHash := string(resp.Body[:min(100, len(resp.Body))])
		uniqueBodies[bodyHash]++

		dur := durations[i]
		totalDur += dur
		if minDur == 0 || dur < minDur {
			minDur = dur
		}
		if dur > maxDur {
			maxDur = dur
		}
	}

	result.UniqueResponses = len(uniqueBodies)
	result.TimingStats = TimingStats{
		MinDuration: minDur,
		MaxDuration: maxDur,
		AvgDuration: totalDur / time.Duration(max(validCount, 1)),
	}

	// Detect potential race conditions
	// Multiple successes when only one should be allowed = RACE!
	if result.SuccessCount > 1 {
		result.PotentialRace = true
		result.Evidence = fmt.Sprintf("%d successful responses when expecting 1", result.SuccessCount)
	}

	// Multiple different success responses
	if result.UniqueResponses > 1 && result.SuccessCount > 0 {
		result.PotentialRace = true
		result.Evidence = fmt.Sprintf("%d unique response bodies detected", result.UniqueResponses)
	}
}

// printResults displays scan results
func (s *Scanner) printResults(result *Result, totalTime time.Duration) {
	fmt.Println()
	
	if result.PotentialRace {
		color.Red("╔═══════════════════════════════════════════════════╗")
		color.Red("║         🔥 POTENTIAL RACE CONDITION! 🔥            ║")
		color.Red("╚═══════════════════════════════════════════════════╝")
		color.Yellow("    Evidence: %s", result.Evidence)
	} else {
		color.Green("[+] No obvious race condition detected")
	}

	fmt.Println()
	color.Cyan("[*] Statistics:")
	color.White("    Total Requests: %d", result.TotalRequests)
	color.White("    Successful (2xx): %d", result.SuccessCount)
	color.White("    Unique Responses: %d", result.UniqueResponses)
	color.White("    Total Time: %v", totalTime)

	fmt.Println()
	color.Cyan("[*] Response Codes:")
	for code, count := range result.ResponseCodes {
		color.White("    %d: %d times", code, count)
	}

	fmt.Println()
	color.Cyan("[*] Timing:")
	color.White("    Min: %v", result.TimingStats.MinDuration)
	color.White("    Max: %v", result.TimingStats.MaxDuration)
	color.White("    Avg: %v", result.TimingStats.AvgDuration)
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}
