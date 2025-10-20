# Endpoint Scanner

A small Python CLI tool that discovers endpoints for given domains and performs safe checks for common web flaws: reflected XSS, basic SQLi indicators, and open-redirects. Results can be exported as JSON and HTML.

Important: Only run this tool against domains you own or have explicit permission to test.

# Features

Crawl a domain (same-origin) to discover links and form action endpoints

Non-destructive checks for:

Reflected XSS (marker reflection)

Basic SQL injection indicators (error patterns & boolean difference)

Open-redirect parameters

Export results to JSON and HTML
