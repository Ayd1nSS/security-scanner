package main

import (
	"crypto/tls"
	"fmt"
	"net/http"
	"os"
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
	if len(os.Args) != 2 {
		fmt.Println("Usage: security-scanner <URL>")
		return
	}

	url := os.Args[1]
	resp, err := http.Get(url)
	if err != nil {
		fmt.Println("Request failed:", err)
		return
	}
	defer resp.Body.Close()

	fmt.Println("Security Headers:")
	headers := []string{
		"Content-Security-Policy",
		"Strict-Transport-Security",
		"X-Content-Type-Options",
		"X-Frame-Options",
		"Referrer-Policy",
		"Permissions-Policy",
	}
	found := 0
	for _, header := range headers {
		if checkHeader(resp, header) {
			found++
		}
	}
	missing := len(headers) - found

	fmt.Println()
	fmt.Println("Summary:")
	fmt.Println("Headers checked:", len(headers))
	fmt.Println("Headers present:", found)
	fmt.Println("Headers missing:", missing)
	checkTLS(resp)
	checkCertificate(resp)

}
