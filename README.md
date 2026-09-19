# Security Scanner

A little security scanner I'm building while learning Go :P

It takes a URL and checks some basic HTTP, TLS, and certificate stuff.

## What it does

* Checks security headers
* Shows HTTP status and status code
* Detects redirects
* Shows the final URL
* Checks TLS version
* Shows the TLS cipher suite
* Shows certificate info
* Checks when the certificate expires
* Warns if a certificate is expired or expires soon

## Security headers

Right now it checks:

* `Content-Security-Policy`
* `Strict-Transport-Security`
* `X-Content-Type-Options`
* `X-Frame-Options`
* `Referrer-Policy`
* `Permissions-Policy`

Missing headers are shown as warnings. They don't automatically mean something is vulnerable.

## Running it

```bash
go run . https://example.com
```

Or build it:

```bash
go build -o security-scanner
./security-scanner https://example.com
```

## Why I'm making this

Mostly to learn Go by actually building something instead of just reading about it.

I'm also using it to learn more about:

* HTTP
* TLS
* Certificates
* Web security
* Networking
* Git/GitHub

## What's next

* Track the full redirect chain
* Add request timeouts
* Better error handling
* JSON output
* Tests
* Docker
* GitHub Actions
* More security checks

## Disclaimer

Only scan websites and systems you own or have permission to test.

I'm still learning, so this is very much a work in progress :P
