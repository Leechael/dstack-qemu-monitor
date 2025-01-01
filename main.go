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

type ProcessInfo struct {
	PID          int     `json:"pid"`
	UUID         string  `json:"uuid"`
	CPUUsage     float64 `json:"cpu_usage"`
	CPUCores     int     `json:"cpu_cores"`
	CPUUsagePerc float64 `json:"cpu_usage_perc"`
	VirtMB       float64 `json:"virt_mb"`
	ResMB        float64 `json:"res_mb"`
	ShrMB        float64 `json:"shr_mb"`
	AllocatedMB  int     `json:"allocated_mb"`
	MemUsagePerc float64 `json:"mem_usage_perc"`
	OOMScore     int     `json:"oom_score"`
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

func parseAllocatedResources(pid int) (cpuCores int, memoryMB int) {
	cmd := exec.Command("ps", "-p", strconv.Itoa(pid), "-o", "command", "--no-headers")
	output, err := cmd.Output()
	if err != nil {
		return 1, 0
	}

	cmdLine := string(output)

	smpRegex := regexp.MustCompile(`-smp\s+(\d+)`)
	if matches := smpRegex.FindStringSubmatch(cmdLine); len(matches) > 1 {
		cpuCores, _ = strconv.Atoi(matches[1])
	}

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
	cpuCores, allocatedMB := parseAllocatedResources(pid)

	cpuUsagePerc := cpuUsage / float64(cpuCores)
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

func formatHeader() string {
	return fmt.Sprintf(colorBold+"%-8s  %-36s  %-16s  %-16s  %-16s  %-10s"+colorReset,
		"PID",
		"UUID",
		"CPU(used/max)",
		"MEM(used/max)",
		"USAGE(cpu/mem)",
		"OOM",
	)
}

// 格式化数值为人类可读格式
func formatMemory(mb float64) string {
	if mb >= 1024 {
		return fmt.Sprintf("%.1fG", mb/1024)
	}
	return fmt.Sprintf("%.0fM", mb)
}

func getUsageColor(usage float64) string {
	switch {
	case usage >= 90:
		return colorRed
	case usage >= 75:
		return colorYellow
	default:
		return colorGreen
	}
}

func formatProcessLine(info ProcessInfo) string {
	// 计算使用率颜色
	cpuColor := getUsageColor(info.CPUUsagePerc)
	memColor := getUsageColor(info.MemUsagePerc)

	// 格式化内存数值
	usedMem := formatMemory(info.ResMB)
	totalMem := formatMemory(float64(info.AllocatedMB))

	return fmt.Sprintf("%-8d  %-36s  %s%5.1f%%/%-4d%s  %s%-7s/%-7s%s  %s%5.1f%%%s/%s%5.1f%%%s  %-10d",
		info.PID,
		info.UUID,
		colorBlue, info.CPUUsage, info.CPUCores, colorReset,
		colorBlue, usedMem, totalMem, colorReset,
		cpuColor, info.CPUUsagePerc, colorReset,
		memColor, info.MemUsagePerc, colorReset,
		info.OOMScore,
	)
}

func getHeader() []string {
	timeStr := time.Now().Format("2006-01-02 15:04:05")
	return []string{
		fmt.Sprintf(colorBold+"QEMU Processes Monitor - %s"+colorReset, timeStr),
		fmt.Sprintf(colorCyan + "Press Ctrl+C to exit" + colorReset),
		strings.Repeat("─", 120), // 使用更好看的分隔线
		formatHeader(),
		strings.Repeat("─", 120),
	}
}

// 优化显示函数
func updateDisplay(processes []ProcessInfo) {
	var currentOutput []string

	// 生成当前输出内容
	currentOutput = append(currentOutput, getHeader()...)

	// 按 CPU 使用率排序
	sort.Slice(processes, func(i, j int) bool {
		return processes[i].CPUUsagePerc > processes[j].CPUUsagePerc
	})

	for _, info := range processes {
		currentOutput = append(currentOutput, formatProcessLine(info))
	}
	currentOutput = append(currentOutput, strings.Repeat("─", 120))

	// 如果是第一次输出，清屏并打印所有内容
	if len(lastOutput) == 0 {
		fmt.Print(clearScreen + moveToTop)
		for _, line := range currentOutput {
			fmt.Println(line)
		}
		lastOutput = currentOutput
		return
	}

	// 移动到屏幕顶部
	fmt.Print(moveToTop)

	// 更新发生变化的行
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
