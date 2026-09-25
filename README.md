# JS Path Extractor 🔍

A lightweight and feature-rich Python tool designed for **Bug Bounty Hunters** and **Pentesters** to extract hidden API endpoints, URLs, nested JavaScript links, and interesting paths from web applications.

## 🚀 Features
- **Dynamic & Nested Link Extraction**: Extracts script references from `<script src="...">`, inline scripts, and automatically discovers nested `.js` file paths referenced inside JavaScript code.
- **Batch Processing via File**: Reads and merges external JS links directly from an input text file (e.g., `link.txt`).
- **Interactive Auth & Retry Handling**: Automatically prompts for authentication and custom headers when encountering `401` or `403` HTTP status codes:
  - Authorization Headers (Bearer / Basic)
  - Cookie Strings
  - Custom Headers (Key: Value)
  - Custom User-Agent Strings
- **Proxy Support**: Integrates with local HTTP/HTTPS proxies (e.g., Burp Suite, Caido) for request inspection and traffic routing.
- **Intelligent Filtering**: Context-aware regex matching that filters out base64 strings, third-party library noise, and code syntax garbage.
- **Flexible JS Downloader**: Downloads all discovered JS files with options to filter out common third-party libraries and preserve directory structures or flatten files into a single directory.

## 📦 Installation

Ensure Python 3 is installed along with the required dependencies:

    pip install requests beautifulsoup4

## ⚡ Usage

### Basic Command
Scan a target URL to extract endpoints and JavaScript paths:

    python extract_js_paths.py [https://example.com](https://example.com)

### Options & Arguments

| Argument | Description |
| :--- | :--- |
| `url` | Target URL to scan (Required) |
| `-p`, `--proxy` | Proxy URL (e.g., `[http://127.0.0.1:8080](http://127.0.0.1:8080)`) |
| `-ua`, `--user-agent` | Custom User-Agent string |
| `-f`, `--file` | Path to text file containing additional JS URLs |

### Examples

**1. Scan via Proxy with Custom User-Agent:**

    python extract_js_paths.py [https://example.com](https://example.com) -p [http://127.0.0.1:8080](http://127.0.0.1:8080) -ua "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"

**2. Load external links file (`link.txt`) and route through Proxy:**

    python extract_js_paths.py [https://example.com](https://example.com) -f link.txt -p [http://127.0.0.1:8080](http://127.0.0.1:8080)

---

### 📄 Input File Format (`link.txt`)
When using the `-f` flag, create a text file with one full URL per line:

    [https://example.com/assets/app.js](https://example.com/assets/app.js)
    [https://example.com/chunks/vendor.js](https://example.com/chunks/vendor.js)
    # Comments starting with # will be ignored
