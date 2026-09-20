package main

import (
	"crypto/tls"
	"encoding/json"
	"fmt"
	"hello-go/internal/scanner"
	"net/http"
	"os"
	"time"
)

func checkHeader(resp *http.Response, name string) bool {
	value := resp.Header.Get(name)

	if value == "" {
		fmt.Println("[WARNING] Missing: ", name)
		return false
	}
	fmt.Println("[FOUND]", name, ":", value)
	return true

}

func checkTLS(resp *http.Response) {
	if resp.TLS == nil {
		fmt.Println("[WARNING] Connection is not using TLS")
		return
	}
	fmt.Println()
	fmt.Println("TLS information:")
	fmt.Println("Version: ", tlsVersion(resp.TLS.Version))
	fmt.Println("Cipher Suite:", tls.CipherSuiteName(resp.TLS.CipherSuite))
}
func checkCertificate(resp *http.Response) {
	if resp.TLS == nil || len(resp.TLS.PeerCertificates) == 0 {
		fmt.Println("[WARNING] No TLS certificate found")
		return
	}

	cert := resp.TLS.PeerCertificates[0]

	fmt.Println()
	fmt.Println("Certificate Information:")
	fmt.Println("Subject:", cert.Subject.CommonName)
	fmt.Println("Issuer:", cert.Issuer.CommonName)
	fmt.Println("Expires:", cert.NotAfter)
	daysRemaining := int(time.Until(cert.NotAfter).Hours() / 24)

	if daysRemaining < 0 {
		fmt.Println("[WARNING] Certificate is expired")
	} else {
		fmt.Println("Days until expiration:", daysRemaining)

		if daysRemaining < 30 {
			fmt.Println("[WARNING] Certificate expires in less than 30 days")
		}
	}
}
func tlsVersion(version uint16) string {
	switch version {
	case tls.VersionTLS10:
		return "TLS 1.0"
	case tls.VersionTLS11:
		return "TLS 1.1"
	case tls.VersionTLS12:
		return "TLS 1.2"
	case tls.VersionTLS13:
		return "TLS 1.3"
	default:
		return "Unknown"
	}
}

func main() {

	jsonOutput := false
	url := ""

	if len(os.Args) == 2 {
		url = os.Args[1]
	} else if len(os.Args) == 3 && os.Args[2] == "--json" {
		url = os.Args[1]
		jsonOutput = true
	} else {
		fmt.Println("Usage: security-scanner <URL> [--json]")
		return
	}
	redirects := []string{}
	client := &http.Client{
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			fmt.Println("[REDIRECT]", req.URL.String())
			return nil
		},
	}

	resp, err := client.Get(url)
	if err != nil {
		fmt.Println("Request failed:", err)
		return
	}
	defer resp.Body.Close()
	fmt.Println("HTTP Information:")
	fmt.Println("Status:", resp.Status)
	fmt.Println("Status Code:", resp.StatusCode)
	fmt.Println("Final URL:", resp.Request.URL.String())
	findings := scanner.CheckHeaders(resp)
	var tlsVersionName string
	var cipherSuiteName string

	if resp.TLS != nil {
		tlsVersionName = tlsVersion(resp.TLS.Version)
		cipherSuiteName = tls.CipherSuiteName(resp.TLS.CipherSuite)
	}

	result := scanner.ScanResult{
		Target:      url,
		Status:      resp.Status,
		StatusCode:  resp.StatusCode,
		FinalURL:    resp.Request.URL.String(),
		Redirects:   redirects,
		Findings:    findings,
		TLSVersion:  tlsVersionName,
		CipherSuite: cipherSuiteName,
	}
	if jsonOutput {
		data, err := json.MarshalIndent(result, "", "  ")
		if err != nil {
			fmt.Println("Failed to generate JSON:", err)
			return
		}

		fmt.Println(string(data))
		return
	}

	fmt.Println("Security Headers:")

	for _, finding := range findings {
		fmt.Printf("[%s] %s - %s - %s\n",
			finding.Status,
			finding.Severity,
			finding.Name,
			finding.Details,
		)
	}
	checkTLS(resp)
	checkCertificate(resp)

}
