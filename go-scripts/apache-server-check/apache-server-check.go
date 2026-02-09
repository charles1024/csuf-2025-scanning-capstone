package main

import (
	"bufio"
	"context"
	"crypto/tls"
	"flag"
	"fmt"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	//potentially change this line to pull from our forked repo instead
	nuclei "github.com/projectdiscovery/nuclei/v3/lib"
	"github.com/projectdiscovery/nuclei/v3/pkg/output"
)

type probeResult struct {
        InputTarget string
        URLTried    string
        Server      string
        Ecosystem   bool 
        Err         error
}

//reads target hosts or URLs from a file or stdin
func readTargets(path string) ([]string, error) {
	var sc *bufio.Scanner
	// if file path is provided, reads 1 target per line from the file
	if path == "" {
		stat, _ := os.Stdin.Stat()
		if (stat.Mode() & os.ModeCharDevice) != 0 {
			return nil, fmt.Errorf("no -l provided and stdin is empty")
		}
		sc = bufio.NewScanner(os.Stdin)
	} 
	// if no path, reads from stdin and errors if empty
	else {
		f, err := os.Open(path)
		if err != nil {
			return nil, err
		}
		defer f.Close()
		sc = bufio.NewScanner(f)
	}

	var out []string
	for sc.Scan() {
		t := strings.TrimSpace(sc.Text())
		if t == "" || strings.HasPrefix(t, "#") {
			continue
		}
		out = append(out, t)
	}
	//returns slice of cleaned target strings or error if input cannot be read
	return out, sc.Err()
}

//constructc an http client suitable for fast probing/fingerprinting
func newHTTPClient(timeout time.Duration, followRedirects bool) *http.Client {
	//uses cutsomt transport with configurable timeout, optional redirect
	transport := &http.Transport{
		Proxy: http.ProxyFromEnvironment,
		DialContext: (&net.Dialer{
			Timeout:   timeout,
			KeepAlive: 30 * time.Second,
		}).DialContext,
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true, // fingerprinting; don't block on cert issues
		},
		ForceAttemptHTTP2: true,
	}
	c := &http.Client{Transport: transport, Timeout: timeout}
	if !followRedirects {
		c.CheckRedirect = func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		}
	}
	return c
}


// Ecosystem gate: include Apache httpd, Tomcat (Apache-Coyote), and Airflow (TornadoServer)
func isApacheEcosystem(serverHeader string) bool {
	s := strings.ToLower(strings.TrimSpace(serverHeader))
	if s == "" {
		return false
	}
	// Apache / Tomcat
	if strings.Contains(s, "apache") || strings.Contains(s, "coyote") {
		return true
	}
	// Airflow commonly advertises TornadoServer
	if strings.Contains(s, "tornado") { // matches "TornadoServer" etc.
		return true
	}
	return false
}

//attemtps to reach root of target over http(s) & collect derver metadeta
func probeRoot(client *http.Client, rawTarget string) probeResult {
	rawTarget = strings.TrimSpace(strings.TrimRight(rawTarget, "/"))

	//if target does not include a scheme, tries https then http
	var tryURLs []string
	if strings.HasPrefix(rawTarget, "http://") || strings.HasPrefix(rawTarget, "https://") {
		tryURLs = []string{rawTarget}
	} else {
		tryURLs = []string{"https://" + rawTarget, "http://" + rawTarget}
	}

	//get request is issued, and server response is extracted
	var lastErr error
	for _, u := range tryURLs {
		req, err := http.NewRequest("GET", u, nil)
		if err != nil {
			lastErr = err
			continue
		}
		req.Header.Set("User-Agent", "apache-ecosystem-prefilter/1.0")
		req.Header.Set("Accept", "*/*")

		resp, err := client.Do(req)
		if err != nil {
			lastErr = err
			continue
		}
		resp.Body.Close()

		server := strings.TrimSpace(resp.Header.Get("Server"))
		return probeResult{
			InputTarget: rawTarget,
			URLTried:    u,
			Server:      server,
			Ecosystem:   true,
			Err:         nil,
		}
	}
	// returns result containing the attempted URL, detected server, ecosystem match, and errors 
	return probeResult{InputTarget: rawTarget, URLTried: "", Server: "", Ecosystem: false, Err: lastErr}
}

func main() {
	var (
		targetsFile     = flag.String("l", "", "targets file (one per line). If omitted, reads stdin")
		workflowPath    = flag.String("w", "master-template.yaml", "path to nuclei workflow yaml")
		concurrency     = flag.Int("c", 30, "prefilter concurrency")
		timeoutSeconds  = flag.Int("timeout", 10, "prefilter timeout seconds")
		followRedirects = flag.Bool("follow-redirects", true, "follow redirects during prefilter")
		quietNonMatches = flag.Bool("quiet-nonmatches", false, "suppress [NO] lines")
	)
	flag.Parse()

	targets, err := readTargets(*targetsFile)
	if err != nil {
		fmt.Fprintf(os.Stderr, "input error: %v\n", err)
		os.Exit(2)
	}
	if len(targets) == 0 {
		fmt.Fprintln(os.Stderr, "no targets")
		os.Exit(2)
	}

	httpClient := newHTTPClient(time.Duration(*timeoutSeconds)*time.Second, *followRedirects)

	// --- Stage 1: prefilter ---
	//concurrent http probing to identify Apache ecosystem
	in := make(chan string)
	out := make(chan probeResult)

	var wg sync.WaitGroup
	for i := 0; i < *concurrency; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for t := range in {
				out <- probeRoot(httpClient, t)
			}
		}()
	}

	go func() {
		for _, t := range targets {
			in <- t
		}
		close(in)
		wg.Wait()
		close(out)
	}()

	var gatedTargets []string
	for r := range out {
		if r.Err != nil {
			fmt.Printf("[PROBE-ERR] %s: %v\n", r.InputTarget, r.Err)
			continue
		}
		if r.Ecosystem {
			if r.Server != "" {
				fmt.Printf("[GATE-IN]   %s -> %s | Server: %s\n", r.InputTarget, r.URLTried, r.Server)
			} else {
				fmt.Printf("[GATE-IN]   %s -> %s | Server: <missing>\n", r.InputTarget, r.URLTried)
			}
			// Use scheme’d URL so templates using {{BaseURL}} behave correctly.
			gatedTargets = append(gatedTargets, r.URLTried)
		} else if !*quietNonMatches {
			if r.Server != "" {
				fmt.Printf("[NO]        %s -> %s | Server: %s\n", r.InputTarget, r.URLTried, r.Server)
			} else {
				fmt.Printf("[NO]        %s -> %s | Server: <missing>\n", r.InputTarget, r.URLTried)
			}
		}
	}

	if len(gatedTargets) == 0 {
		fmt.Println("No Apache/Tomcat/Airflow (Tornado) gated targets found. Exiting.")
		return
	}

	// --- Stage 2: run workflow (still WIP) ---
	//runs workflow against gated targets, reducing noise, and improving scan efficiency
	fmt.Printf("\nRunning workflow %q on %d gated targets...\n\n", *workflowPath, len(gatedTargets))

	//if want noise, can unsilence the verbosity
	ctx := context.Background()
	ne, err := nuclei.NewThreadSafeNucleiEngineCtx(
		ctx,
		nuclei.DisableUpdateCheck(),
		nuclei.WithVerbosity(nuclei.VerbosityOptions{Silent: true}),
		nuclei.WithTemplatesOrWorkflows(nuclei.TemplateSources{
			Workflows: []string{*workflowPath},
		}),
	)
	if err != nil {
		fmt.Fprintf(os.Stderr, "nuclei init error: %v\n", err)
		os.Exit(1)
	}
	defer ne.Close()

	ne.GlobalResultCallback(func(ev *output.ResultEvent) {
		target := ev.Matched
		if target == "" {
			target = ev.Host
		}
		fmt.Printf("[HIT] %s | template=%s\n", target, ev.TemplateID)
	})

	if err := ne.ExecuteNucleiWithOptsCtx(ctx, gatedTargets); err != nil {
		fmt.Fprintf(os.Stderr, "nuclei execute error: %v\n", err)
		os.Exit(1)
	}
}
