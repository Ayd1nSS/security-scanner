package scanner

import (
	"net/http"
	"testing"
)

func TestCheckHeaders(t *testing.T) {
	resp := &http.Response{
		Header: http.Header{
			"Content-Security-Policy": []string{"default-src 'self'"},
			"X-Content-Type-Options":  []string{"nosniff"},
		},
	}

	findings := CheckHeaders(resp)

	if len(findings) != 6 {
		t.Fatalf("expected 6 findings, got %d", len(findings))
	}

	for _, finding := range findings {
		switch finding.Name {
		case "Content-Security-Policy":
			if finding.Status != "PASS" {
				t.Errorf("expected CSP to PASS, got %s", finding.Status)
			}

		case "X-Content-Type-Options":
			if finding.Status != "PASS" {
				t.Errorf("expected X-Content-Type-Options to PASS, got %s", finding.Status)
			}
		}
	}
}

func TestMissingHeaderSeverity(t *testing.T) {
	resp := &http.Response{
		Header: http.Header{},
	}

	findings := CheckHeaders(resp)

	for _, finding := range findings {
		if finding.Status != "WARN" {
			t.Errorf("expected %s to be WARN, got %s",
				finding.Name, finding.Status)
		}
	}

	for _, finding := range findings {
		switch finding.Name {
		case "Content-Security-Policy":
			if finding.Severity != "HIGH" {
				t.Errorf("expected CSP severity HIGH, got %s",
					finding.Severity)
			}

		case "Referrer-Policy":
			if finding.Severity != "LOW" {
				t.Errorf("expected Referrer-Policy severity LOW, got %s",
					finding.Severity)
			}
		}
	}
}
func TestCheckCookies(t *testing.T) {
	resp := &http.Response{
		Header: http.Header{
			"Set-Cookie": []string{
				"session=insecure-demo",
			},
		},
	}

	findings := CheckCookies(resp)

	if len(findings) != 2 {
		t.Fatalf("expected 2 cookie findings, got %d", len(findings))
	}

	for _, finding := range findings {
		if finding.Status != "WARN" {
			t.Errorf("expected cookie finding to be WARN, got %s", finding.Status)
		}
	}
}
func TestCheckServerHeader(t *testing.T) {
	resp := &http.Response{
		Header: http.Header{
			"Server": []string{"nginx/1.24.0"},
		},
	}

	findings := CheckServerHeader(resp)

	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}

	if findings[0].Status != "WARN" {
		t.Errorf("expected Server Header to be WARN, got %s", findings[0].Status)
	}

	if findings[0].Severity != "LOW" {
		t.Errorf("expected Server Header severity LOW, got %s", findings[0].Severity)
	}
}
