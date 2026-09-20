package scanner

import (
	"net/http"
)

type Finding struct {
	Name     string `json:"name"`
	Status   string `json:"status"`
	Severity string `json:"severity"`
	Details  string `json:"details"`
}

type ScanResult struct {
	Target            string    `json:"target"`
	Status            string    `json:"status"`
	StatusCode        int       `json:"status_code"`
	FinalURL          string    `json:"final_url"`
	Redirects         []string  `json:"redirects"`
	Findings          []Finding `json:"findings"`
	TLSVersion        string    `json:"tls_version,omitempty"`
	CipherSuite       string    `json:"cipher_suite,omitempty"`
	CertificateCN     string    `json:"certificate_cn,omitempty"`
	CertificateIssuer string    `json:"certificate_issuer,omitempty"`
	CertificateExpiry string    `json:"certificate_expiry,omitempty"`
}

func CheckHeaders(resp *http.Response) []Finding {
	headers := []struct {
		name     string
		severity string
	}{
		{"Content-Security-Policy", "HIGH"},
		{"Strict-Transport-Security", "MEDIUM"},
		{"X-Content-Type-Options", "MEDIUM"},
		{"X-Frame-Options", "MEDIUM"},
		{"Referrer-Policy", "LOW"},
		{"Permissions-Policy", "LOW"},
	}

	var findings []Finding

	for _, header := range headers {
		if resp.Header.Get(header.name) == "" {
			findings = append(findings, Finding{
				Name:     header.name,
				Status:   "WARN",
				Severity: header.severity,
				Details:  "Header is missing",
			})
		} else {
			findings = append(findings, Finding{
				Name:     header.name,
				Status:   "PASS",
				Severity: "NONE",
				Details:  "Header is present",
			})
		}
	}

	return findings
}
