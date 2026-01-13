/*
Package ui provides terminal UI components for ANANKE.
Uses pterm for beautiful, modern terminal output similar to Tsurugi's Rich-based UI.
*/
package ui

import (
	"fmt"
	"strings"

	"github.com/pterm/pterm"
)

// Colors using pterm
var (
	headerStyle  = pterm.NewStyle(pterm.FgMagenta, pterm.Bold)
	infoStyle    = pterm.NewStyle(pterm.FgCyan)
	successStyle = pterm.NewStyle(pterm.FgGreen, pterm.Bold)
	warningStyle = pterm.NewStyle(pterm.FgYellow, pterm.Bold)
	errorStyle   = pterm.NewStyle(pterm.FgRed, pterm.Bold)
	dimStyle     = pterm.NewStyle(pterm.FgGray)
)

// Banner prints the ANANKE banner with skull mascot
func Banner(version string) {
	// Skull ASCII art
	skull := headerStyle.Sprint(`
        ⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⡀⠀⠀⠀⣰⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
        ⠀⠀⠀⠀⠀⠀⡀⠀⢀⠒⠑⣴⣦⣾⣧⣤⢀⡤⠀⠀⠀⡀⠀⠀⠀
        ⠀⠀⠀⠀⢀⠀⢀⡘⠉⠁⣰⣾⣿⣿⣿⣿⣿⣿⣷⢀⡤⠊⠀⠀⠀⠀
        ⠀⠀⠀⠀⠀⢱⠊⡄⠒⠾⣿⣿⣿⣿⣿⣿⠿⠛⢹⣿⣯⣤⠤⠄⠀⠀
        ⠀⠀⠀⠒⢦⠂⠀⣇⠀⠸⠟⢈⣿⣿⡁⠺⠗⠀⣸⣿⣿⣃⠀⠀⠀⠀
        ⠀⠀⠀⠀⢘⢀⣼⠻⢷⣶⣶⣿⣿⣿⣿⣶⣶⣾⠟⣻⣿⡯⠁⠀⠀⠀
        ⠀⠀⠀⠉⠱⢾⣿⡀⠀⠈⠉⠙⠛⠛⠛⠉⠉⠀⢀⣿⣿⠿⠛⠒⠀⠀
        ⠀⠀⠀⠀⠔⢛⣿⣷⡈⠒⠀⠀⠀⠔⠁⠊⠒⢈⣾⣿⡏⠀⠀⠀⠀⠀
        ⠀⠀⠀⠀⠀⠜⠛⠿⣿⣶⣤⣀⣀⣀⣀⣤⣶⣿⠿⣿⠉⠀⠀⠀⠀⠀
        ⠀⠀⠀⠀⠀⠀⠀⡸⠛⢉⡿⠻⠟⣿⢿⡟⣏⠁⠀⠘⠄⠀⠀⠀⠀⠀
        ⠀⠀⠀⠀⠀⠀⠀⠀⠀⡜⠀⠀⠀⠁⠀⠃⠘⡀⠀⠀`)

	fmt.Println(skull)

	// Title
	pterm.DefaultCenter.Println(
		pterm.NewStyle(pterm.FgCyan, pterm.Bold).Sprint("A N A N K E"),
	)
	pterm.DefaultCenter.Println(
		dimStyle.Sprint("The Goddess of Inevitability"),
	)
	fmt.Println()

	// Info box using pterm
	pterm.DefaultBox.WithTitle("HikariSystem Security Tools").
		WithTitleTopCenter().
		WithBoxStyle(pterm.NewStyle(pterm.FgCyan)).
		Println(fmt.Sprintf(
			"  IDOR Hunter + Race Condition Scanner\n"+
				"  Version: %s", version))
	fmt.Println()
}

// SectionHeader prints a section header
func SectionHeader(title string) {
	pterm.DefaultSection.
		WithStyle(pterm.NewStyle(pterm.FgMagenta, pterm.Bold)).
		Println(title)
}

// Box prints a box with content
func Box(title string, content string) {
	pterm.DefaultBox.
		WithTitle(title).
		WithTitleTopLeft().
		WithBoxStyle(pterm.NewStyle(pterm.FgCyan)).
		Println(content)
}

// SuccessBox prints a success box
func SuccessBox(content string) {
	pterm.DefaultBox.
		WithTitle("SUCCESS").
		WithTitleTopCenter().
		WithBoxStyle(pterm.NewStyle(pterm.FgGreen)).
		Println(content)
}

// ErrorBox prints an error box
func ErrorBox(content string) {
	pterm.DefaultBox.
		WithTitle("ERROR").
		WithTitleTopCenter().
		WithBoxStyle(pterm.NewStyle(pterm.FgRed)).
		Println(content)
}

// WarningBox prints a warning box
func WarningBox(content string) {
	pterm.DefaultBox.
		WithTitle("WARNING").
		WithTitleTopCenter().
		WithBoxStyle(pterm.NewStyle(pterm.FgYellow)).
		Println(content)
}

// Progress prints a progress bar
func ProgressBar(total int, title string) *pterm.ProgressbarPrinter {
	pb, _ := pterm.DefaultProgressbar.
		WithTotal(total).
		WithTitle(title).
		WithBarCharacter("#").
		WithLastCharacter("#").
		WithElapsedTimeRoundingFactor(0).
		Start()
	return pb
}

// Spinner creates and starts a spinner
func Spinner(text string) *pterm.SpinnerPrinter {
	spinner, _ := pterm.DefaultSpinner.
		WithRemoveWhenDone(true).
		Start(text)
	return spinner
}

// Table prints a formatted table
func Table(headers []string, rows [][]string) {
	tableData := pterm.TableData{headers}
	tableData = append(tableData, rows...)

	pterm.DefaultTable.
		WithHasHeader().
		WithBoxed().
		WithHeaderStyle(pterm.NewStyle(pterm.FgCyan, pterm.Bold)).
		WithData(tableData).
		Render()
}

// Log functions
func Info(msg string, args ...interface{}) {
	pterm.Info.Printfln(msg, args...)
}

func Success(msg string, args ...interface{}) {
	pterm.Success.Printfln(msg, args...)
}

func Warning(msg string, args ...interface{}) {
	pterm.Warning.Printfln(msg, args...)
}

func Error(msg string, args ...interface{}) {
	pterm.Error.Printfln(msg, args...)
}

func Debug(msg string, args ...interface{}) {
	pterm.Debug.Printfln(msg, args...)
}

// Finding prints a finding with severity using pterm panels
func Finding(severity, title, detail string) {
	var style pterm.Style
	var prefix string

	switch strings.ToUpper(severity) {
	case "CRITICAL":
		style = *pterm.NewStyle(pterm.FgRed, pterm.Bold, pterm.BgRed)
		prefix = "!!!"
	case "HIGH":
		style = *pterm.NewStyle(pterm.FgRed, pterm.Bold)
		prefix = "!!"
	case "MEDIUM":
		style = *pterm.NewStyle(pterm.FgYellow, pterm.Bold)
		prefix = "!"
	case "LOW":
		style = *pterm.NewStyle(pterm.FgBlue)
		prefix = "~"
	default:
		style = *pterm.NewStyle(pterm.FgWhite)
		prefix = "-"
	}

	fmt.Println()
	pterm.Println(style.Sprintf("[%s] [%s] ", prefix, strings.ToUpper(severity)) +
		pterm.White(title))
	if detail != "" {
		pterm.Println(dimStyle.Sprintf("    +-- %s", detail))
	}
}

// Stats prints scan statistics in a box
func Stats(stats map[string]interface{}) {
	var content string
	for key, value := range stats {
		content += fmt.Sprintf("%-20s %v\n", key+":", value)
	}

	pterm.DefaultBox.
		WithTitle("STATISTICS").
		WithTitleTopCenter().
		WithBoxStyle(pterm.NewStyle(pterm.FgCyan)).
		Println(content)
}

// ScanResult prints scan result summary
func ScanResult(high, medium, low int) {
	fmt.Println()

	if high > 0 {
		pterm.DefaultBox.
			WithTitle("FINDINGS").
			WithTitleTopCenter().
			WithBoxStyle(pterm.NewStyle(pterm.FgRed)).
			Println(fmt.Sprintf(
				"%s %d HIGH confidence\n"+
					"%s %d MEDIUM confidence\n"+
					"%s %d LOW confidence",
				pterm.Red("[!!!]"), high,
				pterm.Yellow("[!!]"), medium,
				pterm.White("[!]"), low))
	} else if medium > 0 {
		pterm.DefaultBox.
			WithTitle("FINDINGS").
			WithTitleTopCenter().
			WithBoxStyle(pterm.NewStyle(pterm.FgYellow)).
			Println(fmt.Sprintf(
				"%s %d MEDIUM confidence\n"+
					"%s %d LOW confidence",
				pterm.Yellow("[!!]"), medium,
				pterm.White("[!]"), low))
	} else if low > 0 {
		pterm.DefaultBox.
			WithTitle("FINDINGS").
			WithTitleTopCenter().
			WithBoxStyle(pterm.NewStyle(pterm.FgWhite)).
			Println(fmt.Sprintf("%s %d LOW confidence", pterm.White("[!]"), low))
	} else {
		pterm.Success.Println("No vulnerabilities detected")
	}
}

// RaceResult prints race condition result box
func RaceResult(potential bool, evidence string, successCount int32, uniqueResponses int) {
	fmt.Println()
	if potential {
		pterm.DefaultBox.
			WithTitle("RACE CONDITION DETECTED").
			WithTitleTopCenter().
			WithBoxStyle(pterm.NewStyle(pterm.FgRed)).
			Println(fmt.Sprintf(
				"Evidence: %s\n"+
					"Successful requests: %d\n"+
					"Unique responses: %d",
				evidence, successCount, uniqueResponses))
	} else {
		pterm.Success.Println("No race condition detected")
	}
}

// ConfigDisplay prints the current scan configuration
func ConfigDisplay(config map[string]string) {
	var content string
	for key, value := range config {
		content += fmt.Sprintf("%-15s %s\n", key+":", value)
	}

	pterm.DefaultBox.
		WithTitle("SCAN CONFIG").
		WithTitleTopLeft().
		WithBoxStyle(pterm.NewStyle(pterm.FgCyan)).
		Println(strings.TrimSuffix(content, "\n"))
}
