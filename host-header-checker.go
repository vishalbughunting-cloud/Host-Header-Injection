package main

import (
	"bufio"
	"crypto/tls"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"
)

type Config struct {
	TargetsFile    string
	OutputFile     string
	Threads        int
	Timeout        int
	FollowRedirect bool
	UserAgent      string
	Verbose        bool
}

type Result struct {
	URL           string
	Vulnerable    bool
	InjectedHost  string
	ResponseCode  int
	Headers       map[string]string
	Error         string
}

var (
	config Config
	client *http.Client
)

func main() {
	// Parse command line flags
	flag.StringVar(&config.TargetsFile, "f", "", "File containing target URLs (one per line)")
	flag.StringVar(&config.OutputFile, "o", "results.txt", "Output file for results")
	flag.IntVar(&config.Threads, "t", 10, "Number of threads")
	flag.IntVar(&config.Timeout, "timeout", 10, "Request timeout in seconds")
	flag.BoolVar(&config.FollowRedirect, "follow-redirects", false, "Follow redirects")
	flag.StringVar(&config.UserAgent, "user-agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36", "Custom User-Agent")
	flag.BoolVar(&config.Verbose, "v", false, "Verbose output")
	
	flag.Parse()

	fmt.Println(`
   ___  _    _  _    ___  _  _    ___  ___   _   _   _   _  _   ___ 
  / __|| |_ | || |_ |_ _|| \| |  / __|/ __| | | | | | | | || | | _ |
 | (__ | ' \| ||  _| | | | .  | | (__ \__ \ | |_| | | |_| || |_|  _/
  \___||_||_|_| \__| |_| |_|\_|  \___||___/  \___/   \___/ |_(_)_|  
                                                                    
                          Host Header Injection Scanner
	`)

	// Setup HTTP client
	client = &http.Client{
		Timeout: time.Duration(config.Timeout) * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if config.FollowRedirect {
				return nil
			}
			return http.ErrUseLastResponse
		},
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
	}

	var targets []string
	
	// Get targets from command line arguments or file
	args := flag.Args()
	if len(args) > 0 {
		targets = args
	} else if config.TargetsFile != "" {
		var err error
		targets, err = readTargetsFromFile(config.TargetsFile)
		if err != nil {
			fmt.Printf("Error reading targets file: %v\n", err)
			os.Exit(1)
		}
	} else {
		fmt.Println("Usage:")
		fmt.Println("  Single target: host-header-checker https://example.com")
		fmt.Println("  Multiple targets: host-header-checker -f targets.txt")
		fmt.Println("  With options: host-header-checker -f targets.txt -o results.txt -t 20")
		fmt.Println("\nOptions:")
		flag.PrintDefaults()
		os.Exit(1)
	}

	// Safety warning for sensitive domains
	for _, target := range targets {
		if !checkIfSafeTarget(target) {
			fmt.Printf("[SECURITY WARNING] Testing %s may require permission!\n", target)
			fmt.Println("Press Ctrl+C to cancel or wait 5 seconds to continue...")
			time.Sleep(5 * time.Second)
			break
		}
	}

	fmt.Printf("[*] Loaded %d targets\n", len(targets))
	fmt.Printf("[*] Using %d threads\n", config.Threads)
	fmt.Printf("[*] Output file: %s\n", config.OutputFile)
	fmt.Printf("[*] Timeout: %d seconds\n", config.Timeout)
	fmt.Println("[*] Starting scan...\n")

	results := scanTargets(targets)
	saveResults(results)
	
	vulnerableCount := countVulnerable(results)
	fmt.Printf("\n[*] Scan completed! Vulnerable: %d/%d - Results saved to: %s\n", 
		vulnerableCount, len(results), config.OutputFile)
}

func checkIfSafeTarget(targetURL string) bool {
	restrictedDomains := []string{
		".gov.in", ".gov.", ".nic.in", ".ac.in",
		".bank", ".insurance", ".healthcare", ".mil",
	}
	
	for _, domain := range restrictedDomains {
		if strings.Contains(targetURL, domain) {
			return false
		}
	}
	return true
}

func readTargetsFromFile(filename string) ([]string, error) {
	file, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var targets []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		target := strings.TrimSpace(scanner.Text())
		if target != "" {
			// Ensure URL has scheme
			if !strings.HasPrefix(target, "http://") && !strings.HasPrefix(target, "https://") {
				target = "https://" + target
			}
			targets = append(targets, target)
		}
	}
	return targets, scanner.Err()
}

func scanTargets(targets []string) []Result {
	var wg sync.WaitGroup
	targetChan := make(chan string, len(targets))
	resultChan := make(chan Result, len(targets))
	
	// Start workers
	for i := 0; i < config.Threads; i++ {
		wg.Add(1)
		go worker(&wg, targetChan, resultChan)
	}
	
	// Send targets to workers
	for _, target := range targets {
		targetChan <- target
	}
	close(targetChan)
	
	// Collect results
	var results []Result
	go func() {
		wg.Wait()
		close(resultChan)
	}()
	
	for result := range resultChan {
		results = append(results, result)
		printResult(result)
	}
	
	return results
}

func worker(wg *sync.WaitGroup, targets <-chan string, results chan<- Result) {
	defer wg.Done()
	
	for target := range targets {
		results <- testHostHeaderInjection(target)
	}
}

func testHostHeaderInjection(targetURL string) Result {
	result := Result{
		URL:     targetURL,
		Headers: make(map[string]string),
	}
	
	// Test payloads for host header injection
	payloads := []string{
		"evil.com",
		"localhost",
		"127.0.0.1",
		"example.com",
		"attacker.com",
		"test.example.com",
	}
	
	// URL parsing - only for validation, not used further
	_, err := url.Parse(targetURL)
	if err != nil {
		result.Error = fmt.Sprintf("URL parse error: %v", err)
		return result
	}

	for _, payload := range payloads {
		if config.Verbose {
			fmt.Printf("[*] Testing %s with payload: %s\n", targetURL, payload)
		}
		
		req, err := http.NewRequest("GET", targetURL, nil)
		if err != nil {
			result.Error = fmt.Sprintf("Request creation error: %v", err)
			continue
		}
		
		// Set various host headers
		req.Host = payload
		req.Header.Set("Host", payload)
		req.Header.Set("X-Forwarded-Host", payload)
		req.Header.Set("X-Host", payload)
		req.Header.Set("X-Forwarded-Server", payload)
		req.Header.Set("X-Original-Host", payload)
		
		// Set User-Agent
		req.Header.Set("User-Agent", config.UserAgent)
		
		resp, err := client.Do(req)
		if err != nil {
			result.Error = fmt.Sprintf("Request error: %v", err)
			continue
		}
		
		// Read response body
		body, _ := io.ReadAll(resp.Body)
		bodyStr := string(body)
		resp.Body.Close()
		
		// Check for injection indicators
		if checkInjection(bodyStr, payload) || 
		   checkHeaders(resp.Header, payload) ||
		   checkLocationHeader(resp.Header, payload) {
			
			result.Vulnerable = true
			result.InjectedHost = payload
			result.ResponseCode = resp.StatusCode
			
			// Capture relevant headers
			for key, values := range resp.Header {
				if isRelevantHeader(key) {
					result.Headers[key] = strings.Join(values, ", ")
				}
			}
			break
		}
		
		// Store response code for non-vulnerable results
		if result.ResponseCode == 0 {
			result.ResponseCode = resp.StatusCode
			for key, values := range resp.Header {
				if isRelevantHeader(key) {
					result.Headers[key] = strings.Join(values, ", ")
				}
			}
		}
	}
	
	return result
}

func checkInjection(body, payload string) bool {
	// Check if payload appears in response body
	if strings.Contains(body, payload) {
		return true
	}
	
	// Check variations
	variations := []string{
		payload,
		strings.ReplaceAll(payload, ".", "-"),
		strings.ToUpper(payload),
		strings.ToLower(payload),
	}
	
	for _, variation := range variations {
		if strings.Contains(body, variation) {
			return true
		}
	}
	
	return false
}

func checkHeaders(headers http.Header, payload string) bool {
	sensitiveHeaders := []string{
		"Location",
		"Content-Security-Policy",
		"X-Forwarded-Host",
		"X-Host",
		"Server",
		"X-Powered-By",
		"Set-Cookie",
	}
	
	for _, header := range sensitiveHeaders {
		if values := headers.Values(header); len(values) > 0 {
			for _, value := range values {
				if strings.Contains(value, payload) {
					return true
				}
			}
		}
	}
	return false
}

func checkLocationHeader(headers http.Header, payload string) bool {
	location := headers.Get("Location")
	if location != "" {
		return strings.Contains(location, payload)
	}
	return false
}

func isRelevantHeader(header string) bool {
	relevantHeaders := []string{
		"host", "location", "server", "x-powered-by", "x-host",
		"x-forwarded-host", "content-security-policy", "content-type",
		"set-cookie", "x-frame-options", "x-content-type-options",
		"cache-control", "pragma", "expires",
	}
	
	headerLower := strings.ToLower(header)
	for _, relHeader := range relevantHeaders {
		if strings.Contains(headerLower, relHeader) {
			return true
		}
	}
	return false
}

func printResult(result Result) {
	if result.Vulnerable {
		fmt.Printf("[?] VULNERABLE: %s\n", result.URL)  // Fixed: result.URL use karo
		fmt.Printf("    Injected Host: %s | Status: %d\n", result.InjectedHost, result.ResponseCode)
	} else if result.Error != "" {
		fmt.Printf("[?] ERROR: %s - %s\n", result.URL, result.Error)
	} else {
		if config.Verbose {
			fmt.Printf("[ ] SAFE: %s - Status: %d\n", result.URL, result.ResponseCode)
		}
	}
}

func saveResults(results []Result) {
	file, err := os.Create(config.OutputFile)
	if err != nil {
		fmt.Printf("Error creating output file: %v\n", err)
		return
	}
	defer file.Close()
	
	writer := bufio.NewWriter(file)
	
	// Write header
	writer.WriteString("Host Header Injection Scan Results\n")
	writer.WriteString("===================================\n\n")
	writer.WriteString(fmt.Sprintf("Scan Date: %s\n", time.Now().Format("2006-01-02 15:04:05")))
	writer.WriteString(fmt.Sprintf("Total Targets: %d\n", len(results)))
	writer.WriteString(fmt.Sprintf("Vulnerable Targets: %d\n", countVulnerable(results)))
	writer.WriteString(fmt.Sprintf("Safe Targets: %d\n\n", len(results)-countVulnerable(results)))
	
	// Write vulnerable results first
	vulnerableFound := false
	for _, result := range results {
		if result.Vulnerable {
			if !vulnerableFound {
				writer.WriteString("VULNERABLE TARGETS:\n")
				writer.WriteString("===================\n\n")
				vulnerableFound = true
			}
			
			writer.WriteString(strings.Repeat("=", 80) + "\n")
			writer.WriteString(fmt.Sprintf("URL: %s\n", result.URL))
			writer.WriteString(fmt.Sprintf("Injected Host: %s\n", result.InjectedHost))
			writer.WriteString(fmt.Sprintf("Status Code: %d\n", result.ResponseCode))
			writer.WriteString("\nHeaders:\n")
			
			if len(result.Headers) > 0 {
				for key, value := range result.Headers {
					writer.WriteString(fmt.Sprintf("  %s: %s\n", key, value))
				}
			} else {
				writer.WriteString("  No relevant headers captured\n")
			}
			writer.WriteString("\n")
		}
	}
	
	// Write safe results if verbose
	if config.Verbose {
		writer.WriteString("\nSAFE TARGETS:\n")
		writer.WriteString("=============\n\n")
		for _, result := range results {
			if !result.Vulnerable && result.Error == "" {
				writer.WriteString(fmt.Sprintf("URL: %s | Status: %d\n", result.URL, result.ResponseCode))
			}
		}
	}
	
	// Write errors
	errorsFound := false
	for _, result := range results {
		if result.Error != "" {
			if !errorsFound {
				writer.WriteString("\nERRORS:\n")
				writer.WriteString("=======\n\n")
				errorsFound = true
			}
			writer.WriteString(fmt.Sprintf("URL: %s\nError: %s\n\n", result.URL, result.Error))
		}
	}
	
	writer.Flush()
}

func countVulnerable(results []Result) int {
	count := 0
	for _, result := range results {
		if result.Vulnerable {
			count++
		}
	}
	return count
}