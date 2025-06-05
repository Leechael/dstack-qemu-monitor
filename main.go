// QEMU Process Monitor
//
// This tool monitors QEMU processes for a specific user, displaying resource usage
// including CPU, memory, and OOM score. It provides both CLI and HTTP interfaces
// for monitoring.
//
// Features:
// - Real-time monitoring of QEMU processes
// - CPU usage tracking (total and per-core percentage)
// - Memory usage tracking (virtual, resident, shared)
// - OOM score monitoring
// - HTTP endpoints for JSON and Prometheus metrics
// - Color-coded output for better visibility
// - Auto-refresh display

package main

import (
	"bufio"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"os/user"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
)

// Version information, will be set during build
var (
	Version   = "dev"
	GitCommit = "unknown"
	BuildTime = "unknown"
)

// ProcessInfo represents the resource usage information for a QEMU process
type ProcessInfo struct {
	PID          int     `json:"pid"`
	UUID         string  `json:"uuid"`
	CPUUsage     float64 `json:"cpu_usage"`      // Raw CPU usage percentage
	CPUCores     int     `json:"cpu_cores"`      // Number of allocated CPU cores
	CPUUsagePerc float64 `json:"cpu_usage_perc"` // CPU usage percentage relative to allocated cores
	VirtMB       float64 `json:"virt_mb"`        // Virtual memory size in MB
	ResMB        float64 `json:"res_mb"`         // Resident memory size in MB
	ShrMB        float64 `json:"shr_mb"`         // Shared memory size in MB
	AllocatedMB  int     `json:"allocated_mb"`   // Allocated memory in MB
	MemUsagePerc float64 `json:"mem_usage_perc"` // Memory usage percentage
	OOMScore     int     `json:"oom_score"`      // OOM score (0-1000)
}

// Config holds the runtime configuration
type Config struct {
	Username      string
	RefreshRate   time.Duration
	ListenAddr    string
	EnableCLI     bool
	EnableMetrics bool
}

// ANSI escape sequences for terminal control
const (
	clearScreen     = "\033[2J"
	clearLine       = "\033[2K"
	moveToTop       = "\033[H"
	hideCursor      = "\033[?25l"
	showCursor      = "\033[?25h"
	moveToLineStart = "\r"
	moveUp          = "\033[1A"
)

// ANSI color codes for output formatting
const (
	colorReset  = "\033[0m"
	colorRed    = "\033[31m"
	colorGreen  = "\033[32m"
	colorYellow = "\033[33m"
	colorBlue   = "\033[34m"
	colorPurple = "\033[35m"
	colorCyan   = "\033[36m"
	colorWhite  = "\033[37m"
	colorBold   = "\033[1m"
)

var (
	// Regex pattern to extract VM UUID from process command line
	uuidRegex = regexp.MustCompile(`/run/vm/([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})/`)

	// Store the last output for differential display updates
	lastOutput []string

	// Global process data with mutex protection
	processData struct {
		sync.RWMutex
		info []ProcessInfo
	}
)

// SystemInfo represents the host system resource information
type SystemInfo struct {
	TotalCPUs     int     // Total number of CPU cores
	TotalMemoryMB int     // Total system memory in MB
	LoadAvg1      float64 // 1 minute load average
	LoadAvg5      float64 // 5 minute load average
	LoadAvg15     float64 // 15 minute load average
}

// Summary represents the aggregated resource usage of all QEMU processes
type Summary struct {
	ProcessCount  int     // Number of QEMU processes
	TotalCPUUsage float64 // Total CPU usage percentage
	TotalMemoryMB float64 // Total memory usage in MB
	TotalCores    int     // Total allocated CPU cores
	TotalMemAlloc int     // Total allocated memory in MB
}

// getCurrentUsername returns the current user's username
func getCurrentUsername() string {
	currentUser, err := user.Current()
	if err != nil {
		log.Fatal(err)
	}
	return currentUser.Username
}

// parseAllocatedResources extracts allocated CPU cores and memory from QEMU command line
func parseAllocatedResources(pid int) (cpuCores int, memoryMB int) {
	cmd := exec.Command("ps", "-p", strconv.Itoa(pid), "-o", "command", "--no-headers")
	output, err := cmd.Output()
	if err != nil {
		return 1, 0
	}

	cmdLine := string(output)

	// Extract CPU cores from -smp parameter
	smpRegex := regexp.MustCompile(`-smp\s+(\d+)`)
	if matches := smpRegex.FindStringSubmatch(cmdLine); len(matches) > 1 {
		cpuCores, _ = strconv.Atoi(matches[1])
	}

	// Extract memory size from -m parameter
	memRegex := regexp.MustCompile(`-m\s+(\d+)(M|G)?`)
	if matches := memRegex.FindStringSubmatch(cmdLine); len(matches) > 1 {
		mem, _ := strconv.Atoi(matches[1])
		unit := "M"
		if len(matches) > 2 {
			unit = matches[2]
		}
		if unit == "G" {
			memoryMB = mem * 1024
		} else {
			memoryMB = mem
		}
	}

	return cpuCores, memoryMB
}

// getQemuProcesses returns a list of QEMU process IDs for the specified user
func getQemuProcesses(username string) []int {
	// Use pgrep with both user and pattern filtering for precise matching
	// -u ensures only processes owned by the specific user are matched
	// -f searches the full command line for "qemu"
	cmd := exec.Command("pgrep", "-u", username, "-f", "qemu")
	output, err := cmd.Output()
	if err != nil {
		return []int{}
	}

	var pids []int
	for _, line := range strings.Split(string(output), "\n") {
		if line == "" {
			continue
		}
		pid, err := strconv.Atoi(line)
		if err == nil {
			pids = append(pids, pid)
		}
	}
	return pids
}

// getProcessUUID extracts the VM UUID from the process command line
func getProcessUUID(pid int) string {
	cmd := exec.Command("ps", "-p", strconv.Itoa(pid), "-f")
	output, err := cmd.Output()
	if err != nil {
		return "N/A"
	}

	matches := uuidRegex.FindStringSubmatch(string(output))
	if len(matches) > 1 {
		return matches[1]
	}
	return "N/A"
}

// readProcFile reads a file from the /proc filesystem
func readProcFile(pid int, filename string) (string, error) {
	path := filepath.Join("/proc", strconv.Itoa(pid), filename)
	content, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	return string(content), nil
}

// getCPUUsage returns the CPU usage percentage for a process
func getCPUUsage(pid int) float64 {
	cmd := exec.Command("ps", "-p", strconv.Itoa(pid), "-o", "%cpu", "--no-headers")
	output, err := cmd.Output()
	if err != nil {
		return 0.0
	}
	cpu, err := strconv.ParseFloat(strings.TrimSpace(string(output)), 64)
	if err != nil {
		return 0.0
	}
	return cpu
}

// getMemoryInfo returns virtual, resident, and shared memory usage in MB
func getMemoryInfo(pid int) (float64, float64, float64) {
	content, err := readProcFile(pid, "status")
	if err != nil {
		return 0, 0, 0
	}

	var vmSize, vmRSS, rssFile, rssShmem int64
	scanner := bufio.NewScanner(strings.NewReader(content))
	for scanner.Scan() {
		line := scanner.Text()
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}

		switch fields[0] {
		case "VmSize:":
			vmSize, _ = strconv.ParseInt(fields[1], 10, 64)
		case "VmRSS:":
			vmRSS, _ = strconv.ParseInt(fields[1], 10, 64)
		case "RssFile:":
			rssFile, _ = strconv.ParseInt(fields[1], 10, 64)
		case "RssShmem:":
			rssShmem, _ = strconv.ParseInt(fields[1], 10, 64)
		}
	}

	return float64(vmSize) / 1024, float64(vmRSS) / 1024, float64(rssFile+rssShmem) / 1024
}

// getOOMScore returns the OOM score for a process
func getOOMScore(pid int) int {
	content, err := readProcFile(pid, "oom_score")
	if err != nil {
		return -1
	}
	score, err := strconv.Atoi(strings.TrimSpace(string(content)))
	if err != nil {
		return -1
	}
	return score
}

// getProcessInfo collects all resource usage information for a process
func getProcessInfo(pid int) ProcessInfo {
	cpuUsage := getCPUUsage(pid)
	virtMB, resMB, shrMB := getMemoryInfo(pid)
	oomScore := getOOMScore(pid)
	uuid := getProcessUUID(pid)
	cpuCores, allocatedMB := parseAllocatedResources(pid)

	// Calculate CPU usage percentage relative to allocated cores
	cpuUsagePerc := (cpuUsage / float64(cpuCores*100)) * 100
	memUsagePerc := resMB / float64(allocatedMB) * 100

	return ProcessInfo{
		PID:          pid,
		UUID:         uuid,
		CPUUsage:     cpuUsage,
		CPUCores:     cpuCores,
		CPUUsagePerc: cpuUsagePerc,
		VirtMB:       virtMB,
		ResMB:        resMB,
		ShrMB:        shrMB,
		AllocatedMB:  allocatedMB,
		MemUsagePerc: memUsagePerc,
		OOMScore:     oomScore,
	}
}

// formatHeader returns the formatted header string for the display
func formatHeader() string {
	return fmt.Sprintf(colorBold+"%-8s  %-36s  %21s  %34s  %10s"+colorReset,
		"PID",
		"UUID",
		"used % max",
		"virt res shr max %",
		"OOM",
	)
}

// formatMemory formats memory values in a human-readable format (MB/GB)
func formatMemory(mb float64) string {
	if mb >= 1024 {
		return fmt.Sprintf("%.1fG", mb/1024)
	}
	return fmt.Sprintf("%.0fM", mb)
}

// formatProcessLine formats a single process line for display
func formatProcessLine(info ProcessInfo) string {
	// Format memory values
	virtMem := formatMemory(info.VirtMB)
	resMem := formatMemory(info.ResMB)
	shrMem := formatMemory(info.ShrMB)
	totalMem := formatMemory(float64(info.AllocatedMB))

	// Format OOM score with sign
	oomScore := fmt.Sprintf("%+d", info.OOMScore)

	return fmt.Sprintf("%-8d  %-36s  %s%5.1f%% %5.1f%% %2dvcpu%s  %s%6s %6s %6s %7s %5.1f%%%s  %10s",
		info.PID,
		info.UUID,
		colorCyan, info.CPUUsage, info.CPUUsagePerc, info.CPUCores, colorReset,
		colorPurple, virtMem, resMem, shrMem, totalMem, info.MemUsagePerc, colorReset,
		oomScore,
	)
}

// getHeader returns the complete header including timestamp and instructions
func getHeader() []string {
	timeStr := time.Now().Format("2006-01-02 15:04:05")
	sysInfo := getSystemInfo()

	processData.RLock()
	summary := calculateSummary(processData.info)
	processData.RUnlock()

	return []string{
		fmt.Sprintf(colorBold+"QEMU Processes Monitor v%s (%s) - %s"+colorReset, Version, GitCommit[:7], timeStr),
		formatSummary(sysInfo, summary),
		fmt.Sprintf(colorCyan + "Press Ctrl+C to exit" + colorReset),
		strings.Repeat("─", 120),
		formatHeader(),
		strings.Repeat("─", 120),
	}
}

// updateDisplay updates the terminal display with current process information
func updateDisplay(processes []ProcessInfo) {
	var currentOutput []string

	// Generate current output content
	currentOutput = append(currentOutput, getHeader()...)

	// Sort processes by CPU usage percentage
	sort.Slice(processes, func(i, j int) bool {
		return processes[i].CPUUsagePerc > processes[j].CPUUsagePerc
	})

	for _, info := range processes {
		currentOutput = append(currentOutput, formatProcessLine(info))
	}
	currentOutput = append(currentOutput, strings.Repeat("─", 120))

	// Handle first display
	if len(lastOutput) == 0 {
		fmt.Print(clearScreen + moveToTop)
		for _, line := range currentOutput {
			fmt.Println(line)
		}
		lastOutput = currentOutput
		return
	}

	// Update changed lines only
	fmt.Print(moveToTop)
	maxLines := max(len(currentOutput), len(lastOutput))
	for i := 0; i < maxLines; i++ {
		fmt.Print(clearLine)
		if i < len(currentOutput) {
			fmt.Println(currentOutput[i])
		} else {
			fmt.Println()
		}
	}

	lastOutput = currentOutput
}

// max returns the larger of two integers
func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}

// updateProcessData updates the global process information
func updateProcessData(username string) {
	var infos []ProcessInfo
	for _, pid := range getQemuProcesses(username) {
		infos = append(infos, getProcessInfo(pid))
	}

	processData.Lock()
	processData.info = infos
	processData.Unlock()
}

// HTTP Handlers

// handleJSON serves process information in JSON format
func handleJSON(w http.ResponseWriter, r *http.Request) {
	processData.RLock()
	defer processData.RUnlock()

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(processData.info)
}

// handlePrometheus serves process information in Prometheus metrics format
func handlePrometheus(w http.ResponseWriter, r *http.Request) {
	processData.RLock()
	defer processData.RUnlock()

	w.Header().Set("Content-Type", "text/plain")

	// Write Prometheus metrics
	for _, p := range processData.info {
		fmt.Fprintf(w, "# HELP qemu_process_cpu_usage CPU usage in percentage per core\n")
		fmt.Fprintf(w, "qemu_process_cpu_usage{pid=\"%d\",uuid=\"%s\"} %f\n", p.PID, p.UUID, p.CPUUsage)
		fmt.Fprintf(w, "# HELP qemu_process_cpu_cores Allocated CPU cores\n")
		fmt.Fprintf(w, "qemu_process_cpu_cores{pid=\"%d\",uuid=\"%s\"} %d\n", p.PID, p.UUID, p.CPUCores)
		fmt.Fprintf(w, "# HELP qemu_process_cpu_usage_percentage CPU usage percentage relative to allocated cores\n")
		fmt.Fprintf(w, "qemu_process_cpu_usage_percentage{pid=\"%d\",uuid=\"%s\"} %f\n", p.PID, p.UUID, p.CPUUsagePerc)
		fmt.Fprintf(w, "# HELP qemu_process_memory_usage_mb Current memory usage in MB\n")
		fmt.Fprintf(w, "qemu_process_memory_usage_mb{pid=\"%d\",uuid=\"%s\"} %f\n", p.PID, p.UUID, p.ResMB)
		fmt.Fprintf(w, "# HELP qemu_process_memory_allocated_mb Allocated memory in MB\n")
		fmt.Fprintf(w, "qemu_process_memory_allocated_mb{pid=\"%d\",uuid=\"%s\"} %d\n", p.PID, p.UUID, p.AllocatedMB)
		fmt.Fprintf(w, "# HELP qemu_process_memory_usage_percentage Memory usage percentage\n")
		fmt.Fprintf(w, "qemu_process_memory_usage_percentage{pid=\"%d\",uuid=\"%s\"} %f\n", p.PID, p.UUID, p.MemUsagePerc)
		fmt.Fprintf(w, "# HELP qemu_process_oom_score OOM score\n")
		fmt.Fprintf(w, "qemu_process_oom_score{pid=\"%d\",uuid=\"%s\"} %d\n", p.PID, p.UUID, p.OOMScore)
	}
}

// startHTTPServer starts the HTTP server for metrics endpoints
func startHTTPServer(listenAddr string) {
	http.HandleFunc("/metrics", handlePrometheus)
	http.HandleFunc("/json", handleJSON)

	log.Printf("Starting HTTP server on %s", listenAddr)
	go func() {
		if err := http.ListenAndServe(listenAddr, nil); err != nil {
			log.Fatalf("HTTP server error: %v", err)
		}
	}()
}

// runCLI runs the command-line interface
func runCLI(conf *Config, done chan bool) {
	ticker := time.NewTicker(conf.RefreshRate)
	defer ticker.Stop()

	fmt.Print(hideCursor)
	defer fmt.Print(showCursor)

	for {
		select {
		case <-ticker.C:
			processData.RLock()
			updateDisplay(processData.info)
			processData.RUnlock()
		case <-done:
			return
		}
	}
}

// getSystemInfo retrieves system resource information
func getSystemInfo() SystemInfo {
	var info SystemInfo

	// Get CPU count from /proc/cpuinfo
	content, err := os.ReadFile("/proc/cpuinfo")
	if err == nil {
		// Count processor entries in /proc/cpuinfo
		processors := strings.Count(string(content), "processor")
		if processors > 0 {
			info.TotalCPUs = processors
		}
	}

	// Get total memory from /proc/meminfo
	content, err = os.ReadFile("/proc/meminfo")
	if err == nil {
		scanner := bufio.NewScanner(strings.NewReader(string(content)))
		for scanner.Scan() {
			line := scanner.Text()
			if strings.HasPrefix(line, "MemTotal:") {
				fields := strings.Fields(line)
				if len(fields) >= 2 {
					memKB, _ := strconv.ParseInt(fields[1], 10, 64)
					info.TotalMemoryMB = int(memKB / 1024)
					break
				}
			}
		}
	}

	// Get load averages from /proc/loadavg
	content, err = os.ReadFile("/proc/loadavg")
	if err == nil {
		fields := strings.Fields(string(content))
		if len(fields) >= 3 {
			info.LoadAvg1, _ = strconv.ParseFloat(fields[0], 64)
			info.LoadAvg5, _ = strconv.ParseFloat(fields[1], 64)
			info.LoadAvg15, _ = strconv.ParseFloat(fields[2], 64)
		}
	}

	return info
}

// calculateSummary calculates summary statistics for all processes
func calculateSummary(processes []ProcessInfo) Summary {
	var summary Summary
	summary.ProcessCount = len(processes)

	for _, p := range processes {
		summary.TotalCPUUsage += p.CPUUsage
		summary.TotalMemoryMB += p.ResMB
		summary.TotalCores += p.CPUCores
		summary.TotalMemAlloc += p.AllocatedMB
	}

	return summary
}

// formatSummary formats the summary line
func formatSummary(sys SystemInfo, sum Summary) string {
	return fmt.Sprintf(colorBold+"System: %d CPUs, %s RAM, Load: %.2f %.2f %.2f | QEMU: %d procs, CPU: %.1f%% (%d cores), MEM: %s/%s (%.1f%%)"+colorReset,
		sys.TotalCPUs,
		formatMemory(float64(sys.TotalMemoryMB)),
		sys.LoadAvg1, sys.LoadAvg5, sys.LoadAvg15,
		sum.ProcessCount,
		sum.TotalCPUUsage,
		sum.TotalCores,
		formatMemory(sum.TotalMemoryMB),
		formatMemory(float64(sum.TotalMemAlloc)),
		(sum.TotalMemoryMB/float64(sum.TotalMemAlloc))*100,
	)
}

func main() {
	// Command line arguments
	username := flag.String("u", getCurrentUsername(), "Specify username")
	refreshRate := flag.Duration("r", 2*time.Second, "Refresh rate (e.g., 2s, 1m)")
	listenAddr := flag.String("l", "", "HTTP server listen address (e.g., 127.0.0.1:8080)")
	noCLI := flag.Bool("no-cli", false, "Disable command-line interface")
	flag.Parse()

	conf := &Config{
		Username:      *username,
		RefreshRate:   *refreshRate,
		ListenAddr:    *listenAddr,
		EnableCLI:     !*noCLI,
		EnableMetrics: *listenAddr != "",
	}

	// Set up signal handling
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	// Start HTTP server
	if conf.EnableMetrics {
		startHTTPServer(conf.ListenAddr)
	}

	// Start data update goroutine
	done := make(chan bool)
	go func() {
		for {
			updateProcessData(conf.Username)
			time.Sleep(conf.RefreshRate)
		}
	}()

	// Start CLI
	if conf.EnableCLI {
		go runCLI(conf, done)
	}

	// Wait for signal
	<-sigChan
	close(done)
	fmt.Print(showCursor + "\n")
}
