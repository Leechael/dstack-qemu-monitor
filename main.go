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
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
)

type ProcessInfo struct {
	PID      int     `json:"pid"`
	UUID     string  `json:"uuid"`
	CPUUsage float64 `json:"cpu_usage"`
	VirtMB   float64 `json:"virt_mb"`
	ResMB    float64 `json:"res_mb"`
	ShrMB    float64 `json:"shr_mb"`
	OOMScore int     `json:"oom_score"`
}

type Config struct {
	Username      string
	RefreshRate   time.Duration
	ListenAddr    string
	EnableCLI     bool
	EnableMetrics bool
}

// ANSI escape sequences
const (
	clearScreen     = "\033[2J"
	clearLine       = "\033[2K"
	moveToTop       = "\033[H"
	hideCursor      = "\033[?25l"
	showCursor      = "\033[?25h"
	moveToLineStart = "\r"
	moveUp          = "\033[1A"
)

var (
	uuidRegex   = regexp.MustCompile(`/run/vm/([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})/`)
	lastOutput  []string
	processData struct {
		sync.RWMutex
		info []ProcessInfo
	}
)

func getCurrentUsername() string {
	currentUser, err := user.Current()
	if err != nil {
		log.Fatal(err)
	}
	return currentUser.Username
}

func getQemuProcesses(username string) []int {
	cmd := exec.Command("pgrep", "-f", fmt.Sprintf("qemu.*%s", username))
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

func readProcFile(pid int, filename string) (string, error) {
	path := filepath.Join("/proc", strconv.Itoa(pid), filename)
	content, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	return string(content), nil
}

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

func getProcessInfo(pid int) ProcessInfo {
	cpuUsage := getCPUUsage(pid)
	virtMB, resMB, shrMB := getMemoryInfo(pid)
	oomScore := getOOMScore(pid)
	uuid := getProcessUUID(pid)

	return ProcessInfo{
		PID:      pid,
		UUID:     uuid,
		CPUUsage: cpuUsage,
		VirtMB:   virtMB,
		ResMB:    resMB,
		ShrMB:    shrMB,
		OOMScore: oomScore,
	}
}

func formatProcessLine(info ProcessInfo) string {
	return fmt.Sprintf("%-10d %-37s %-10.1f %-15.2f %-15.2f %-15.2f %-10d",
		info.PID, info.UUID, info.CPUUsage, info.VirtMB, info.ResMB, info.ShrMB, info.OOMScore)
}

func getHeader() []string {
	return []string{
		fmt.Sprintf("QEMU Processes Monitor - %s", time.Now().Format("2006-01-02 15:04:05")),
		"Press Ctrl+C to exit",
		"----------------------------------------",
		fmt.Sprintf("%-10s %-37s %-10s %-15s %-15s %-15s %-10s",
			"PID", "UUID", "CPU%", "VIRT(MB)", "RES(MB)", "SHR(MB)", "OOM_SCORE"),
	}
}

func updateDisplay(processes []ProcessInfo) {
	var currentOutput []string

	// Generate current output content
	currentOutput = append(currentOutput, getHeader()...)
	for _, info := range processes {
		currentOutput = append(currentOutput, formatProcessLine(info))
	}

	// If it's the first output, clear the screen and print all content
	if len(lastOutput) == 0 {
		fmt.Print(clearScreen + moveToTop)
		for _, line := range currentOutput {
			fmt.Println(line)
		}
		lastOutput = currentOutput
		return
	}

	// Move to the top of the screen
	fmt.Print(moveToTop)

	// Update changed lines, keep unchanged lines as is
	maxLines := max(len(currentOutput), len(lastOutput))
	for i := 0; i < maxLines; i++ {
		// Clear current line
		fmt.Print(clearLine)

		// Print current line content
		if i < len(currentOutput) {
			fmt.Println(currentOutput[i])
		} else {
			fmt.Println() // Print empty line to clear excess old lines
		}
	}

	lastOutput = currentOutput
}

func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}

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
func handleJSON(w http.ResponseWriter, r *http.Request) {
	processData.RLock()
	defer processData.RUnlock()

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(processData.info)
}

func handlePrometheus(w http.ResponseWriter, r *http.Request) {
	processData.RLock()
	defer processData.RUnlock()

	w.Header().Set("Content-Type", "text/plain")

	// Write Prometheus metrics
	for _, p := range processData.info {
		fmt.Fprintf(w, "qemu_process_cpu_usage{pid=\"%d\",uuid=\"%s\"} %f\n", p.PID, p.UUID, p.CPUUsage)
		fmt.Fprintf(w, "qemu_process_memory_virtual_mb{pid=\"%d\",uuid=\"%s\"} %f\n", p.PID, p.UUID, p.VirtMB)
		fmt.Fprintf(w, "qemu_process_memory_resident_mb{pid=\"%d\",uuid=\"%s\"} %f\n", p.PID, p.UUID, p.ResMB)
		fmt.Fprintf(w, "qemu_process_memory_shared_mb{pid=\"%d\",uuid=\"%s\"} %f\n", p.PID, p.UUID, p.ShrMB)
		fmt.Fprintf(w, "qemu_process_oom_score{pid=\"%d\",uuid=\"%s\"} %d\n", p.PID, p.UUID, p.OOMScore)
	}
}

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

func runCLI(conf *Config, done chan bool) {
	ticker := time.NewTicker(conf.RefreshRate)
	defer ticker.Stop()

	// Hide cursor
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
