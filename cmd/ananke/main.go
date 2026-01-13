/*
ANANKE (Ἀνάγκη) - The Goddess of Inevitability
IDOR Hunter + Race Condition Scanner

"Inevitability finds every vulnerability"

HikariSystem Security Tools
*/
package main

import (
	"fmt"
	"os"
	"time"

	"github.com/fatih/color"
	"github.com/spf13/cobra"

	"github.com/hikarisystem/ananke/pkg/idor"
	"github.com/hikarisystem/ananke/pkg/race"
	"github.com/hikarisystem/ananke/pkg/ui"
)

var version = "0.1.0"

// Global flags
var (
	authHeader string
	cookie     string
	threads    int
	timeout    int
	outputFile string
	verbose    bool
)

func printBanner() {
	ui.Banner(version)
}

func main() {
	rootCmd := &cobra.Command{
		Use:   "ananke",
		Short: "ANANKE - IDOR Hunter + Race Condition Scanner",
		Long: `ANANKE (Ἀνάγκη) - The Goddess of Inevitability

A high-performance security scanner for finding:
  • IDOR (Insecure Direct Object References)
  • Race Conditions (TOCTOU, Double Spending)
  • Business Logic Flaws`,
		Run: func(cmd *cobra.Command, args []string) {
			printBanner()
			cmd.Help()
		},
	}

	// Global flags
	rootCmd.PersistentFlags().StringVarP(&authHeader, "auth", "H", "", "Authorization header (e.g., 'Bearer TOKEN')")
	rootCmd.PersistentFlags().StringVarP(&cookie, "cookie", "c", "", "Cookie string")
	rootCmd.PersistentFlags().IntVarP(&threads, "threads", "t", 10, "Number of concurrent threads")
	rootCmd.PersistentFlags().IntVar(&timeout, "timeout", 10, "Request timeout in seconds")
	rootCmd.PersistentFlags().StringVarP(&outputFile, "output", "o", "", "Output file (JSON)")
	rootCmd.PersistentFlags().BoolVarP(&verbose, "verbose", "v", false, "Verbose output")

	// Add subcommands
	rootCmd.AddCommand(idorCmd())
	rootCmd.AddCommand(raceCmd())
	rootCmd.AddCommand(versionCmd())

	if err := rootCmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}

// IDOR command
func idorCmd() *cobra.Command {
	var (
		idRange     string
		paramName   string
		compareAuth string
		strict      bool
	)

	cmd := &cobra.Command{
		Use:   "idor [url]",
		Short: "Scan for IDOR vulnerabilities",
		Long: `Scan for Insecure Direct Object Reference vulnerabilities.

The URL should contain a placeholder {id} that will be fuzzed.

Examples:
  ananke idor "https://api.target.com/users/{id}" --range 1-1000
  ananke idor "https://api.target.com/orders/{id}" -H "Bearer TOKEN" --range 1-100 --strict`,
		Args: cobra.ExactArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			printBanner()
			targetURL := args[0]

			color.Green("[*] IDOR SCANNER")
			color.White("    Target: %s", targetURL)
			color.White("    Range: %s", idRange)
			color.White("    Threads: %d", threads)
			if strict {
				color.Yellow("    Mode: STRICT (only sensitive data)")
			}
			fmt.Println()

			// Create scanner config
			cfg := &idor.Config{
				URL:         targetURL,
				IDRange:     idRange,
				ParamName:   paramName,
				CompareAuth: compareAuth,
				Threads:     threads,
				Verbose:     verbose,
				Strict:      strict,
				AuthHeader:  authHeader,
				Cookie:      cookie,
			}

			// Create and run scanner
			scanner := idor.NewScanner(cfg)
			results, err := scanner.Scan(cfg)
			if err != nil {
				color.Red("[!] Error: %v", err)
				os.Exit(1)
			}

			// Count findings by confidence
			var high, medium, low int
			for _, r := range results {
				if r.Interesting {
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

			fmt.Println()
			if high > 0 {
				color.Red("[!!!] Found %d HIGH confidence IDOR vulnerabilities!", high)
			}
			if medium > 0 && !strict {
				color.Yellow("[!!] Found %d MEDIUM confidence findings", medium)
			}
			if low > 0 && verbose && !strict {
				color.White("[!] Found %d LOW confidence findings", low)
			}
			if high == 0 && medium == 0 && low == 0 {
				color.Green("[+] No IDOR vulnerabilities detected")
			}
		},
	}

	cmd.Flags().StringVar(&idRange, "range", "1-100", "ID range to fuzz (e.g., 1-1000)")
	cmd.Flags().StringVarP(&paramName, "param", "p", "id", "Parameter name to fuzz")
	cmd.Flags().StringVar(&compareAuth, "compare", "", "Second auth token for comparison")
	cmd.Flags().BoolVar(&strict, "strict", false, "Only report HIGH confidence findings with sensitive data")

	return cmd
}

// Race condition command
func raceCmd() *cobra.Command {
	var (
		method      string
		body        string
		raceThreads int
		delay       int
	)

	cmd := &cobra.Command{
		Use:   "race [url]",
		Short: "Test for race conditions",
		Long: `Test for race condition vulnerabilities.

Sends multiple concurrent requests to detect TOCTOU issues.

Examples:
  ananke race "https://api.target.com/redeem" -X POST -d '{"coupon":"DISCOUNT"}' --threads 100
  ananke race "https://api.target.com/transfer" -X POST -d '{"amount":100}' -H "Bearer TOKEN"`,
		Args: cobra.ExactArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			printBanner()
			targetURL := args[0]

			color.Yellow("[*] RACE CONDITION SCANNER")
			color.White("    Target: %s", targetURL)
			color.White("    Method: %s", method)
			color.White("    Threads: %d", raceThreads)
			color.White("    Delay: %dμs", delay)
			fmt.Println()

			// Create scanner config
			cfg := &race.Config{
				URL:        targetURL,
				Method:     method,
				Body:       []byte(body),
				Threads:    raceThreads,
				Delay:      time.Duration(delay) * time.Microsecond,
				AuthHeader: authHeader,
				Cookie:     cookie,
				Verbose:    verbose,
			}

			// Create and run scanner
			scanner := race.NewScanner(cfg)
			result, err := scanner.Scan(cfg)
			if err != nil {
				color.Red("[!] Error: %v", err)
				os.Exit(1)
			}

			fmt.Println()
			if result.PotentialRace {
				color.Red("[!] Potential race condition detected!")
			} else {
				color.Green("[+] No race condition detected")
			}
		},
	}

	cmd.Flags().StringVarP(&method, "method", "X", "POST", "HTTP method")
	cmd.Flags().StringVarP(&body, "data", "d", "", "Request body")
	cmd.Flags().IntVar(&raceThreads, "threads", 50, "Number of concurrent race threads")
	cmd.Flags().IntVar(&delay, "delay", 0, "Delay between requests in microseconds")

	return cmd
}

// Version command
func versionCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "version",
		Short: "Print version",
		Run: func(cmd *cobra.Command, args []string) {
			fmt.Printf("ANANKE v%s\n", version)
			fmt.Printf("HikariSystem Security Tools\n")
		},
	}
}
