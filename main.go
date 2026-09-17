package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"strconv"
	"sync"
	"time"

	"github.com/rivo/tview"
)

// Cloudflare API response.
// The real /client/v4/ips response nests CIDRs as
// {"result": {"ipv4_cidrs": [...], "ipv6_cidrs": [...], "etag": "..."}},
// not as a flat array of {cidr, ip, mask, ip_range} objects.
type CloudflareResponse struct {
	Success bool `json:"success"`
	Result  struct {
		IPv4CIDRs []string `json:"ipv4_cidrs"`
		IPv6CIDRs []string `json:"ipv6_cidrs"`
		Etag      string   `json:"etag"`
	} `json:"result"`
}

// portTask is a single unit of scan work handed to a worker.
type portTask struct {
	ip   string
	port int
}

// Scan result hold single ip scan
type ScanResult struct {
	IP      string
	Port    int
	Open    bool
	Latency time.Duration
	Error   error
}

// stats holds realtime scanning stats
type Stats struct {
	TotalIPs   int
	Scanned    int
	OpenPorts  int
	ClosePorts int
	mu         sync.Mutex
}

func (s *Stats) Increment(scanned bool, open bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if scanned {
		s.Scanned++
	}
	if open {
		s.OpenPorts++
	} else {
		s.ClosePorts++
	}
}

func (s *Stats) Get() (totalIPs int, scanned int, openPorts int, closePorts int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.TotalIPs, s.Scanned, s.OpenPorts, s.ClosePorts
}

func fetchCloudflareIPs() ([]string, error) {
	url := "https://api.cloudflare.com/client/v4/ips"
	response, err := http.Get(url)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch API: %w", err)
	}
	defer response.Body.Close()

	var cloudFlareResponse CloudflareResponse
	if err := json.NewDecoder(response.Body).Decode(&cloudFlareResponse); err != nil {
		return nil, fmt.Errorf("failed to decode API response: %w", err)
	}
	if !cloudFlareResponse.Success {
		return nil, fmt.Errorf("API response indicates failure")
	}

	// BUG FIX: result.ipv4_cidrs / result.ipv6_cidrs are already plain string
	// slices of CIDR blocks — no per-item "cidr" field to pull out.
	var cidrs []string
	cidrs = append(cidrs, cloudFlareResponse.Result.IPv4CIDRs...)
	cidrs = append(cidrs, cloudFlareResponse.Result.IPv6CIDRs...)
	return cidrs, nil
}

// expandCIDR converts a CIDR block into a list of individual IP strings.
func expandCIDR(cidr string) ([]string, error) {
	ip, ipnet, err := net.ParseCIDR(cidr)
	if err != nil {
		return nil, err
	}
	var ips []string
	for ip := ip.Mask(ipnet.Mask); ipnet.Contains(ip); incrementIP(ip) {
		// Copy the IP since incrementIP mutates the underlying bytes in place.
		ipCopy := make(net.IP, len(ip))
		copy(ipCopy, ip)
		ips = append(ips, ipCopy.String())
		if len(ips) > 65535 {
			break
		}
	}
	return ips, nil
}

func incrementIP(ip net.IP) {
	for j := len(ip) - 1; j >= 0; j-- {
		ip[j]++
		if ip[j] > 0 {
			break
		}
	}
}

func scanPort(ctx context.Context, ip string, port int, _ time.Duration) ScanResult {
	start := time.Now()
	var d net.Dialer
	conn, err := d.DialContext(ctx, "tcp", net.JoinHostPort(ip, strconv.Itoa(port)))
	latency := time.Since(start)

	result := ScanResult{
		IP:      ip,
		Port:    port,
		Latency: latency,
	}
	if err != nil {
		result.Open = false
		result.Error = err
		return result
	}
	defer conn.Close()

	result.Open = true
	return result
}
func main() {
	targetPorts := []int{80, 443, 2053, 2082, 2083, 2086, 2087, 2095, 2096}
	concurrency := 100
	timeout := 2 * time.Second
	maxTotalIPs := 5000

	// 1. Fetch Cloudflare IPs
	fmt.Println("Fetching Cloudflare IP ranges...")
	cidrRanges, err := fetchCloudflareIPs()
	if err != nil {
		fmt.Printf("Error fetching Cloudflare IPs: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("Fetched %d CIDR ranges from Cloudflare.\n", len(cidrRanges))

	// 2. Expand IP lists from CIDR ranges.
	var allIPs []string
	for _, cidr := range cidrRanges {
		if len(allIPs) >= maxTotalIPs {
			break
		}
		ips, err := expandCIDR(cidr)
		if err != nil {
			fmt.Printf("Error expanding CIDR %s: %v\n", cidr, err)
			continue
		}
		for _, ip := range ips {
			if len(allIPs) >= maxTotalIPs {
				break
			}
			allIPs = append(allIPs, ip)
		}
	}
	fmt.Printf("Prepared %d IPs to scan.\n", len(allIPs))

	totalTask := len(allIPs) * len(targetPorts)
	stats := &Stats{TotalIPs: totalTask}

	// 3. Setup TUI
	app := tview.NewApplication()

	progressBar := tview.NewTextView()
	progressBar.SetDynamicColors(true)
	progressBar.SetBorder(true)
	progressBar.SetTitle(" Progress ")

	statusBox := tview.NewTextView()
	statusBox.SetDynamicColors(true)
	statusBox.SetBorder(true)
	statusBox.SetTitle(" Live Statistics ")

	resultsList := tview.NewTable()
	resultsList.SetBorders(false)
	resultsList.SetSelectable(true, false)
	resultsList.SetBorder(true)
	resultsList.SetTitle(" Open Ports Found (Live) ")

	// Layout
	grid := tview.NewGrid().
		SetRows(3, 10, 0).
		SetColumns(0).
		AddItem(progressBar, 0, 0, 1, 1, 0, 0, false).
		AddItem(statusBox, 1, 0, 1, 1, 0, 0, false).
		AddItem(resultsList, 2, 0, 1, 1, 0, 0, false)

	rootPage := tview.NewFlex().SetDirection(tview.FlexRow).
		AddItem(grid, 0, 1, false)

	app.SetRoot(rootPage, true)

	// Worker pool
	taskChan := make(chan portTask, concurrency*2)
	var wg sync.WaitGroup

	// Update UI in a separate goroutine.
	go func() {
		ticker := time.NewTicker(200 * time.Millisecond)
		defer ticker.Stop()
		for range ticker.C {
			_, scanned, openPorts, closePorts := stats.Get()
			if totalTask > 0 {
				pct := float64(scanned) / float64(totalTask) * 100
				progressBar.SetText(fmt.Sprintf("[yellow]Scanning... [green]%.2f%%[white] (%d/%d)", pct, scanned, totalTask))
			}
			statusBox.Clear()
			fmt.Fprintf(statusBox, "[yellow]Total Tasks:[white] %d\n", totalTask)
			fmt.Fprintf(statusBox, "[green]Scanned:[white] %d\n", scanned)
			fmt.Fprintf(statusBox, "[red]Open:[white] %d\n", openPorts)
			fmt.Fprintf(statusBox, "[gray]Closed/Filtered:[white] %d\n", closePorts)
			fmt.Fprintf(statusBox, "[blue]Concurrency:[white] %d\n", concurrency)

			app.Draw()
		}
	}()

	for i := 0; i < concurrency; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for t := range taskChan {
				ctx, cancel := context.WithTimeout(context.Background(), timeout)
				result := scanPort(ctx, t.ip, t.port, timeout)
				cancel()
				stats.Increment(true, result.Open)
				if result.Open {
					app.QueueUpdateDraw(func() {
						row := resultsList.GetRowCount()
						resultsList.SetCell(row, 0, tview.NewTableCell(result.IP))
						resultsList.SetCell(row, 1, tview.NewTableCell(strconv.Itoa(result.Port)))
						resultsList.SetCell(row, 2, tview.NewTableCell(fmt.Sprintf("%v", result.Latency)))
					})
				}
			}
		}()
	}

	// Dispatcher
	go func() {
		for _, ip := range allIPs {
			for _, port := range targetPorts {
				taskChan <- portTask{ip: ip, port: port}
			}
		}
		close(taskChan)
		wg.Wait()
		app.Stop() // Exit app when done (tview uses Stop, not Quit)
	}()

	// Run App
	if err := app.Run(); err != nil {
		panic(err)
	}

	fmt.Println("\nScan completed successfully.")
}