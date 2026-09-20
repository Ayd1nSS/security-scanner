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
func CheckCookies(resp *http.Response) []Finding {
	var findings []Finding

	for _, cookie := range resp.Cookies() {
		if !cookie.Secure {
			findings = append(findings, Finding{
				Name:     "Cookie Secure flag",
				Status:   "WARN",
				Severity: "MEDIUM",
				Details:  "Cookie " + cookie.Name + " is missing the Secure flag",
			})
		}

		if !cookie.HttpOnly {
			findings = append(findings, Finding{
				Name:     "Cookie HttpOnly flag",
				Status:   "WARN",
				Severity: "MEDIUM",
				Details:  "Cookie " + cookie.Name + " is missing the HttpOnly flag",
			})
		}

		if cookie.SameSite == http.SameSiteDefaultMode {
			findings = append(findings, Finding{
				Name:     "Cookie SameSite",
				Status:   "WARN",
				Severity: "LOW",
				Details:  "Cookie " + cookie.Name + " does not explicitly define SameSite",
			})
		}
	}

	return findings
}
func CheckServerHeader(resp *http.Response) []Finding {
	server := resp.Header.Get("Server")

	if server == "" {
		return []Finding{
			{
				Name:     "Server Header",
				Status:   "PASS",
				Severity: "NONE",
				Details:  "Server header is not exposed",
			},
		}
	}

	return []Finding{
		{
			Name:     "Server Header",
			Status:   "WARN",
			Severity: "LOW",
			Details:  "Server header exposes: " + server,
		},
	}
}
