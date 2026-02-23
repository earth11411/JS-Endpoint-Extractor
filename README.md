# JS Path Extractor 🔍

A lightweight Python tool designed for **Bug Bounty Hunters** and **Pentesters** to extract hidden API endpoints, URLs, and interesting paths from JavaScript files found on a target website.

## 🚀 Features
- Extracts URLs and paths from both `<script src="...">` and **inline scripts**.
- **Intelligent Filtering**: Ignores junk data, base64 strings, and common library noise.
- **Context Awareness**: Detects paths based on variable names like `api`, `url`, `route`, `endpoint`.
- **Downloader**: Optional feature to download all discovered JS files for offline analysis.

## 📦 Installation
pip install requests beautifulsoup4

## ⚡ Usage
python extract_js_paths.py https://example.com
