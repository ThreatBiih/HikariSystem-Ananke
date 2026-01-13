/*
Package idor provides IDOR vulnerability detection.
Fuzzes object IDs and compares responses to detect access control issues.
Now with enhanced false positive filtering and sensitive data detection.
*/
package idor

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/ThreatBiih/HikariSystem-Ananke/pkg/http"
	"github.com/fatih/color"
	"github.com/google/uuid"
)

// Sensitive data patterns for IDOR detection
var sensitivePatterns = map[string]*regexp.Regexp{
	// Personal Identifiable Information (PII)
	"email": regexp.MustCompile(`"(?:email|e-mail|mail)":\s*"([^"]+@[^"]+\.[^"]+)"`),
	"phone": regexp.MustCompile(`"(?:phone|telefone|mobile|celular)":\s*"(\+?[\d\s\-\(\)]{8,20})"`),
	"cpf":   regexp.MustCompile(`"(?:cpf|document|documento)":\s*"?(\d{3}\.?\d{3}\.?\d{3}-?\d{2})"?`),
	"cnpj":  regexp.MustCompile(`"(?:cnpj)":\s*"?(\d{2}\.?\d{3}\.?\d{3}/?\d{4}-?\d{2})"?`),
	"ssn":   regexp.MustCompile(`"(?:ssn|social_security)":\s*"?(\d{3}-?\d{2}-?\d{4})"?`),

	// Financial Data
	"credit_card":  regexp.MustCompile(`"(?:card|cartao|credit_card|card_number)":\s*"?(\d{4}[\s\-]?\d{4}[\s\-]?\d{4}[\s\-]?\d{4})"?`),
	"bank_account": regexp.MustCompile(`"(?:account|conta|bank_account)":\s*"?(\d{5,20})"?`),
	"balance":      regexp.MustCompile(`"(?:balance|saldo|amount)":\s*"?(\d+\.?\d*)"?`),

	// Authentication/Session Data
	"password": regexp.MustCompile(`"(?:password|senha|pass|pwd)":\s*"([^"]+)"`),
	"token":    regexp.MustCompile(`"(?:token|access_token|auth_token|api_key)":\s*"([^"]+)"`),
	"secret":   regexp.MustCompile(`"(?:secret|api_secret|private_key)":\s*"([^"]+)"`),

	// Address Data
	"address": regexp.MustCompile(`"(?:address|endereco|street|rua)":\s*"([^"]{10,})"`),
	"zip":     regexp.MustCompile(`"(?:zip|cep|postal_code)":\s*"?(\d{5}-?\d{3}|\d{5})"?`),

	// User Identifiers
	"user_id":      regexp.MustCompile(`"(?:user_id|userId|usuario_id)":\s*"?([^",\s]+)"?`),
	"private_name": regexp.MustCompile(`"(?:full_name|nome_completo|first_name|last_name)":\s*"([^"]+)"`),
}

// Public content patterns (likely false positives)
var publicPatterns = []*regexp.Regexp{
	regexp.MustCompile(`<title>.*(?:404|Not Found|Não Encontrado).*</title>`),
	regexp.MustCompile(`<meta\s+name="robots"\s+content="index`),
	regexp.MustCompile(`<article`),
	regexp.MustCompile(`<nav`),
	regexp.MustCompile(`class="(?:post|article|news|noticia|blog)"`),
}

// Scanner performs IDOR scanning
type Scanner struct {
	client  *http.Client
	threads int
	verbose bool
	strict  bool // Strict mode: only report if sensitive data found
	results []Result
	mu      sync.Mutex
}

// Result represents a potential IDOR finding
type Result struct {
	URL           string           `json:"url"`
	OriginalID    string           `json:"original_id,omitempty"`
	FuzzedID      string           `json:"fuzzed_id"`
	StatusCode    int              `json:"status_code"`
	BodyLength    int              `json:"body_length"`
	Different     bool             `json:"different"`
	Interesting   bool             `json:"interesting"`
	SensitiveData []SensitiveMatch `json:"sensitive_data,omitempty"`
	Confidence    string           `json:"confidence,omitempty"`
	Duration      time.Duration    `json:"duration_ns"`
}

// SensitiveMatch holds info about detected sensitive data
type SensitiveMatch struct {
	Type    string `json:"type"`
	Pattern string `json:"pattern"`
	Sample  string `json:"sample"`
}

// Config holds scanner configuration
type Config struct {
	URL         string
	IDRange     string   // e.g., "1-1000"
	UUIDMode    string   // "random", "increment", "file"
	UUIDCount   int      // Number of UUIDs to generate
	ParamName   string   // e.g., "id"
	CompareAuth string   // Second auth token for comparison
	Wordlist    []string // Custom ID wordlist
	Threads     int
	Verbose     bool
	Strict      bool // Only report real IDOR with sensitive data
	AuthHeader  string
	Cookie      string
	OutputFile  string // JSON output file
}

// NewScanner creates a new IDOR scanner
func NewScanner(cfg *Config) *Scanner {
	opts := []http.Option{
		http.WithTimeout(10 * time.Second),
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
		verbose: cfg.Verbose,
		strict:  cfg.Strict,
	}
}

// Scan performs the IDOR scan
func (s *Scanner) Scan(cfg *Config) ([]Result, error) {
	// Parse ID range
	ids, err := s.parseIDRange(cfg.IDRange)
	if err != nil {
		return nil, err
	}

	// Add wordlist IDs
	ids = append(ids, cfg.Wordlist...)

	color.Cyan("[*] Starting IDOR scan with %d IDs...", len(ids))
	if s.strict {
		color.Yellow("[*] STRICT MODE: Only reporting findings with sensitive data")
	}
	fmt.Println()

	// Get baseline response
	baselineURL := strings.Replace(cfg.URL, "{id}", ids[0], 1)
	baseline, err := s.client.Get(baselineURL)
	if err != nil {
		return nil, fmt.Errorf("baseline request failed: %w", err)
	}

	// Check if baseline is public content (likely false positive source)
	isPublicContent := s.isPublicContent(baseline.Body)
	if isPublicContent {
		color.Yellow("[!] Warning: Baseline appears to be public content")
		color.Yellow("    False positive rate may be high. Use --strict for better results.")
	}

	color.White("    Baseline: %s (Status: %d, Size: %d)",
		baselineURL, baseline.StatusCode, len(baseline.Body))

	// Create work channel
	jobs := make(chan string, len(ids))
	resultsChan := make(chan Result, len(ids))

	// Start workers
	var wg sync.WaitGroup
	for i := 0; i < s.threads; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for id := range jobs {
				result := s.testID(cfg.URL, id, baseline)
				resultsChan <- result
			}
		}()
	}

	// Send jobs
	for _, id := range ids[1:] { // Skip baseline ID
		jobs <- id
	}
	close(jobs)

	// Collect results
	go func() {
		wg.Wait()
		close(resultsChan)
	}()

	// Process results
	var highConf, medConf, lowConf int
	for result := range resultsChan {
		s.mu.Lock()
		s.results = append(s.results, result)
		s.mu.Unlock()

		if result.Interesting {
			switch result.Confidence {
			case "HIGH":
				highConf++
				s.printFinding(result)
			case "MEDIUM":
				medConf++
				if !s.strict {
					s.printFinding(result)
				}
			case "LOW":
				lowConf++
				if s.verbose && !s.strict {
					s.printFinding(result)
				}
			}
		} else if s.verbose {
			s.printResult(result)
		}
	}

	// Summary
	fmt.Println()
	color.Cyan("[*] Scan Summary:")
	color.Red("    HIGH confidence: %d", highConf)
	color.Yellow("    MEDIUM confidence: %d", medConf)
	if !s.strict {
		color.White("    LOW confidence: %d", lowConf)
	}

	return s.results, nil
}

// testID tests a single ID
func (s *Scanner) testID(urlTemplate, id string, baseline *http.Response) Result {
	url := strings.Replace(urlTemplate, "{id}", id, 1)

	resp, err := s.client.Get(url)
	if err != nil {
		return Result{
			URL:        url,
			FuzzedID:   id,
			StatusCode: 0,
		}
	}

	// Analyze response
	different := !bytes.Equal(resp.Body, baseline.Body)
	sensitiveMatches := s.detectSensitiveData(resp.Body)
	interesting, confidence := s.analyzeResponse(resp, baseline, sensitiveMatches)

	return Result{
		URL:           url,
		FuzzedID:      id,
		StatusCode:    resp.StatusCode,
		BodyLength:    len(resp.Body),
		Different:     different,
		Interesting:   interesting,
		SensitiveData: sensitiveMatches,
		Confidence:    confidence,
		Duration:      resp.Duration,
	}
}

// detectSensitiveData scans response for sensitive data patterns
func (s *Scanner) detectSensitiveData(body []byte) []SensitiveMatch {
	var matches []SensitiveMatch

	for dataType, pattern := range sensitivePatterns {
		if match := pattern.Find(body); match != nil {
			// Redact the sample for safety
			sample := string(match)
			if len(sample) > 30 {
				sample = sample[:15] + "..." + sample[len(sample)-10:]
			}

			matches = append(matches, SensitiveMatch{
				Type:    dataType,
				Pattern: pattern.String()[:min(40, len(pattern.String()))],
				Sample:  sample,
			})
		}
	}

	return matches
}

// isPublicContent checks if response looks like public content
func (s *Scanner) isPublicContent(body []byte) bool {
	for _, pattern := range publicPatterns {
		if pattern.Match(body) {
			return true
		}
	}
	return false
}

// analyzeResponse determines if response indicates IDOR and confidence level
func (s *Scanner) analyzeResponse(resp, baseline *http.Response, sensitiveMatches []SensitiveMatch) (bool, string) {
	// 403/401 bypass is always HIGH confidence
	if resp.StatusCode == 200 && (baseline.StatusCode == 401 || baseline.StatusCode == 403) {
		if len(sensitiveMatches) > 0 {
			return true, "HIGH"
		}
		return true, "MEDIUM"
	}

	// Not a success response
	if resp.StatusCode != 200 {
		return false, ""
	}

	// Same content = not interesting
	if bytes.Equal(resp.Body, baseline.Body) {
		return false, ""
	}

	// Has sensitive data = HIGH confidence
	if len(sensitiveMatches) > 0 {
		// Check for high-value sensitive data
		for _, m := range sensitiveMatches {
			switch m.Type {
			case "password", "token", "secret", "credit_card", "cpf", "ssn":
				return true, "HIGH"
			}
		}
		return true, "MEDIUM"
	}

	// Public content = probably false positive
	if s.isPublicContent(resp.Body) {
		return false, ""
	}

	// Size difference check (might be different user data)
	sizeDiff := float64(len(resp.Body)-len(baseline.Body)) / float64(max(len(baseline.Body), 1))
	if sizeDiff > 0.2 || sizeDiff < -0.2 { // 20% difference
		return true, "LOW"
	}

	return false, ""
}

// parseIDRange parses a range like "1-1000" into a slice of IDs
func (s *Scanner) parseIDRange(rangeStr string) ([]string, error) {
	parts := strings.Split(rangeStr, "-")
	if len(parts) != 2 {
		return nil, fmt.Errorf("invalid range format: %s", rangeStr)
	}

	start, err := strconv.Atoi(parts[0])
	if err != nil {
		return nil, err
	}

	end, err := strconv.Atoi(parts[1])
	if err != nil {
		return nil, err
	}

	ids := make([]string, 0, end-start+1)
	for i := start; i <= end; i++ {
		ids = append(ids, strconv.Itoa(i))
	}

	return ids, nil
}

// printFinding prints an IDOR finding with confidence
func (s *Scanner) printFinding(r Result) {
	var confColor *color.Color
	switch r.Confidence {
	case "HIGH":
		confColor = color.New(color.FgRed, color.Bold)
	case "MEDIUM":
		confColor = color.New(color.FgYellow, color.Bold)
	default:
		confColor = color.New(color.FgWhite)
	}

	confColor.Printf("[%s] ", r.Confidence)
	color.Red("POTENTIAL IDOR: %s", r.URL)
	color.White("    ID: %s | Status: %d | Size: %d | Time: %v",
		r.FuzzedID, r.StatusCode, r.BodyLength, r.Duration)

	// Print sensitive data found
	if len(r.SensitiveData) > 0 {
		color.Yellow("    Sensitive data detected:")
		for _, m := range r.SensitiveData {
			color.Yellow("      - %s: %s", m.Type, m.Sample)
		}
	}
}

// printResult prints a normal result
func (s *Scanner) printResult(r Result) {
	if r.Different {
		color.White("    [~] %s (Status: %d, Size: %d)", r.FuzzedID, r.StatusCode, r.BodyLength)
	} else {
		color.New(color.FgWhite, color.Faint).Printf("    [=] %s (Status: %d, Same)\n", r.FuzzedID, r.StatusCode)
	}
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

// GenerateUUIDs generates UUIDs based on mode
func GenerateUUIDs(mode string, count int, baseUUID string) ([]string, error) {
	var uuids []string

	switch mode {
	case "random":
		// Generate random UUIDs (v4)
		for i := 0; i < count; i++ {
			uuids = append(uuids, uuid.New().String())
		}

	case "increment":
		// Increment last segment of UUID
		if baseUUID == "" {
			baseUUID = "00000000-0000-0000-0000-000000000001"
		}
		base, err := uuid.Parse(baseUUID)
		if err != nil {
			return nil, fmt.Errorf("invalid base UUID: %w", err)
		}

		bytes := base[:]
		for i := 0; i < count; i++ {
			uuids = append(uuids, uuid.UUID(bytes).String())
			// Increment last byte
			for j := 15; j >= 0; j-- {
				bytes[j]++
				if bytes[j] != 0 {
					break
				}
			}
		}

	case "sequential":
		// Simple sequential UUIDs with incrementing suffix
		for i := 1; i <= count; i++ {
			uuids = append(uuids, fmt.Sprintf("00000000-0000-0000-0000-%012d", i))
		}

	default:
		return nil, fmt.Errorf("unknown UUID mode: %s (use: random, increment, sequential)", mode)
	}

	return uuids, nil
}

// ScanReport contains full scan results for JSON/HTML export
type ScanReport struct {
	Target      string    `json:"target"`
	ScanType    string    `json:"scan_type"`
	StartTime   time.Time `json:"start_time"`
	EndTime     time.Time `json:"end_time"`
	TotalTests  int       `json:"total_tests"`
	Findings    []Result  `json:"findings"`
	HighCount   int       `json:"high_count"`
	MediumCount int       `json:"medium_count"`
	LowCount    int       `json:"low_count"`
}

// SaveJSON saves results to a JSON file
func SaveJSON(filename string, results []Result, target string) error {
	// Filter only interesting results
	var findings []Result
	var high, medium, low int

	for _, r := range results {
		if r.Interesting {
			findings = append(findings, r)
			switch r.Confidence {
			case "HIGH":
				high++
			case "MEDIUM":
				medium++
			case "LOW":
				low++
			}
		}
	}

	report := ScanReport{
		Target:      target,
		ScanType:    "IDOR",
		StartTime:   time.Now(),
		EndTime:     time.Now(),
		TotalTests:  len(results),
		Findings:    findings,
		HighCount:   high,
		MediumCount: medium,
		LowCount:    low,
	}

	data, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal JSON: %w", err)
	}

	if err := os.WriteFile(filename, data, 0644); err != nil {
		return fmt.Errorf("failed to write file: %w", err)
	}

	color.Green("[+] Results saved to: %s", filename)
	return nil
}
