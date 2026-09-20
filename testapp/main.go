package main

import (
	"fmt"
	"net/http"
)

func homeHandler(w http.ResponseWriter, r *http.Request) {
	fmt.Fprintln(w, "<h1>My Test App</h1>")
	fmt.Fprintln(w, "<p>This app is intentionally insecure.</p>")
}

func secureHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Security-Policy", "default-src 'self'")
	w.Header().Set("Strict-Transport-Security", "max-age=31536000")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("X-Frame-Options", "DENY")
	w.Header().Set("Referrer-Policy", "strict-origin-when-cross-origin")
	w.Header().Set("Permissions-Policy", "geolocation=()")

	fmt.Fprintln(w, "<h1>Secure Test App</h1>")
}

func main() {
	http.HandleFunc("/insecure", homeHandler)
	http.HandleFunc("/secure", secureHandler)

	fmt.Println("Test app running on http://localhost:8080")
	http.ListenAndServe(":8080", nil)
}
