import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse
import re
import sys
import argparse
import os

def get_js_links(url):
    """Fetches the URL and extracts all src attributes from script tags and inline script content."""
    try:
        response = requests.get(url, timeout=10, verify=False)
        response.raise_for_status()
        soup = BeautifulSoup(response.text, 'html.parser')
        
        js_links = []
        inline_scripts = []
        
        for script in soup.find_all('script'):
            if script.get('src'):
                full_url = urljoin(url, script.get('src'))
                js_links.append(full_url)
            elif script.string:
                inline_scripts.append(script.string)
        
        if url.lower().endswith('.js'):
            js_links.append(url)
            
        return list(set(js_links)), inline_scripts
    except requests.exceptions.RequestException as e:
        print(f"[-] Error fetching base URL {url}: {e}")
        return [], []

def is_garbage(s):
    """Check if the string is likely garbage/base64/obfuscated code or library schema."""
    # 1. Validation messages and schema definitions (e.g., ": object expected")
    if ': ' in s or ' expected' in s.lower():
        return True

    # 2. Obvious JS code fragments or logic
    code_indicators = [
        '===', '==', '&&', '||', 'this.', 'const ', 'var ', 'let ', 'return ', 
        'function', '=>', 'new ', 'null:', 'undefined', 'typeof ', 'instanceof',
        'document.', 'window.', 'onClick', '{', '}', '[', ']', '(', ')'
    ]
    if any(ind in s for ind in code_indicators):
        return True

    # 3. Leading dots followed by library namespaces (e.g., .dot.v4...)
    if s.startswith('.') and not any(s.lower().endswith(ext) for ext in ['.php', '.js', '.css', '.html']):
        if s.count('.') > 1: # Multiple dots like .dot.v4.Blob
            return True

    # 4. Strings starting/ending with problematic characters
    if s.startswith((')', '(', '+', ',', ';', ':', '!', '=', '}', '{', '[', ']', '*')):
        return True
    if s.endswith(('(', '+', ',', ';', ':', '!', '=', '{', '[', '.', '?', '&')):
        return True

    # 5. Long strings without path structure
    if len(s) > 40 and '/' not in s and '.' not in s:
        return True
    
    # 6. Base64-like check
    if len(s) > 20 and re.match(r'^[a-zA-Z0-9+/=]{20,}$', s):
        if not any(ext in s.lower() for ext in ['.php', '.asp', '.jsp', '.json', '.xml', '.aspx', '.ashx']):
            return True
            
    # 7. Library namespaces and common metadata
    garbage_patterns = [
        r'^styled-components', r'^@angular', r'^@babel', r'^moment/', r'^react',
        r'^[a-f0-9]{32}$', # MD5
        r'^\${.*}$', # Pure template variables
        r'^text/', r'^image/', r'^application/', # Mime
        r'www\.w3\.org', r'ns\.adobe\.com', r'http://schemas\.', 
        r'^[A-Z0-9_/]{15,}$', # Constants
    ]
    for pattern in garbage_patterns:
        if re.search(pattern, s, re.IGNORECASE):
            return True
            
    return False

def extract_endpoints(content):
    """Uses advanced regex and context analysis to find potential API endpoints and paths."""
    endpoints = []
    
    # 1. Context-based matching (High confidence)
    context_regex = r"""(?:path|url|uri|endpoint|host|api|request|route|action|src|href)\s*[:=]\s*(?:"|'|`)([^"'`\s>]+)(?:"|'|`)"""
    context_matches = re.findall(context_regex, content, re.IGNORECASE)
    endpoints.extend(context_matches)

    # 2. String-based matching (Cleaned regex)
    string_regex = r"""(?:"|'|`)([^"'`]{3,})(?:"|'|`)"""
    all_strings = re.findall(string_regex, content)
    
    backend_extensions = ('.php', '.aspx', '.asp', '.jsp', '.json', '.action', '.do', '.ashx', '.asmx', '.cgi')
    path_indicators = ('/', './', '../', 'http://', 'https://', '//')

    for s in all_strings:
        s = s.strip()
        if is_garbage(s): continue

        # Case A: Has a path indicator at the start
        if any(s.startswith(ind) for ind in path_indicators):
            # Strict regex for path characters
            if s.startswith('/') and len(s) > 1 and not re.match(r'^/[a-zA-Z0-9_\-\./\${}:?&=]+$', s):
                continue
            endpoints.append(s)
        # Case B: Has a backend extension
        elif any(ext in s.lower() for ext in backend_extensions):
            endpoints.append(s)
        # Case C: Looks like a REST endpoint (lowercase, with slashes)
        elif '/' in s and re.match(r'^[a-z0-9_\-\./]+$', s): 
            if not s.lower().endswith(('.js', '.css', '.png', '.jpg', '.jpeg', '.svg', '.gif', '.woff', '.woff2', '.ttf', '.map')):
                endpoints.append(s)
        # Case D: Specific interesting keywords
        elif s.lower() in ('login', 'logout', 'signup', 'api', 'admin', 'status', 'auth', 'config', 'v1', 'v2'):
            endpoints.append(s)

    # Cleanup and final filtering
    cleaned = []
    exclude_list = {
        'use strict', 'utf-8', 'object', 'string', 'number', 'boolean', 'undefined', 'null',
        'true', 'false', 'width', 'height', 'padding', 'margin', 'border', 'display', 'error'
    }
    
    for e in set(endpoints):
        # Remove template tags for checking
        check_e = re.sub(r'\${.*?}', 'VAR', e).strip("'\"` ").split('?')[0].split('#')[0]
        
        if not check_e or len(check_e) < 2: continue
        if check_e.lower() in exclude_list: continue
        if is_garbage(check_e): continue
        
        # Must have / or . or be a keyword
        if '/' not in e and '.' not in e and e.lower() not in ('api', 'admin', 'login', 'status'):
            continue
            
        # Final safety against code fragments: too many symbols
        code_chars = sum(1 for c in e if c in '(){}[]!=<>:')
        if len(e) > 0 and (code_chars / len(e) > 0.15):
            continue

        cleaned.append(e)
        
    return list(set(cleaned))

def scan_js_file(js_url):
    """Fetches a JS file and searches for paths inside strings."""
    try:
        response = requests.get(js_url, timeout=10, verify=False)
        response.raise_for_status()
        content = response.text
        return extract_endpoints(content)
    except requests.exceptions.RequestException as e:
        print(f"[-] Error fetching JS {js_url}: {e}")
        return []

def download_js_files(js_urls, flatten=False):
    """Downloads the list of JS files, optionally preserving directory structure."""
    print(f"\n[*] Preparing to download {len(js_urls)} files...")
    
    base_dir = "downloaded_js"
    if not os.path.exists(base_dir):
        os.makedirs(base_dir)

    for url in js_urls:
        try:
            parsed_url = urlparse(url)
            
            if flatten:
                # Get only the filename
                filename = os.path.basename(parsed_url.path)
                if not filename or not filename.endswith('.js'):
                    filename = f"script_{abs(hash(url))}.js"
                
                local_path = os.path.join(base_dir, filename)
                
                # Handle collision if file already exists
                if os.path.exists(local_path):
                     name, ext = os.path.splitext(filename)
                     local_path = os.path.join(base_dir, f"{name}_{str(abs(hash(url)))[:6]}{ext}")
            else:
                # Remove leading slash to ensure os.path.join works correctly
                url_path = parsed_url.path.lstrip('/')
                
                # Construct the local file path
                local_path = os.path.join(base_dir, url_path)
                
                # Handle cases where the path is empty or ends with a slash
                if not url_path or url_path.endswith('/'):
                     local_path = os.path.join(local_path, f"script_{abs(hash(url))}.js")

                # Create necessary directories
                os.makedirs(os.path.dirname(local_path), exist_ok=True)

            print(f"  -> Downloading: {url} -> {local_path} ...", end=" ")
            response = requests.get(url, timeout=10, verify=False)
            response.raise_for_status()
            with open(local_path, 'wb') as f:
                f.write(response.content)
            print("Done")
        except Exception as e:
            print(f"Failed ({e})")

def main():
    parser = argparse.ArgumentParser(description="Clean & Precise JS Path Extractor")
    parser.add_argument("url", help="Target URL to scan")
    args = parser.parse_args()

    target_url = args.url
    print(f"[*] Scanning target: {target_url}")
    
    requests.packages.urllib3.disable_warnings(requests.packages.urllib3.exceptions.InsecureRequestWarning)
    js_urls, inline_scripts = get_js_links(target_url)
    
    if not js_urls and not inline_scripts:
        print("[-] No JavaScript found.")
        return

    print(f"[*] Found {len(js_urls)} JS files and {len(inline_scripts)} inline scripts.")

    all_found = {}
    for js_url in js_urls:
        print(f"  -> Checking: {js_url}")
        found_paths = scan_js_file(js_url)
        if found_paths:
            all_found[js_url] = found_paths

    if inline_scripts:
        print(f"  -> Checking inline scripts...")
        for i, script in enumerate(inline_scripts):
            found_paths = extract_endpoints(script)
            if found_paths:
                all_found[f"Inline Script #{i+1}"] = found_paths

    found_any = False
    for source, paths in all_found.items():
        if paths:
            found_any = True
            print(f"\n[+] {len(paths)} PATHS FOUND in {source}:")
            # Sort paths to put more interesting ones at the top
            for path in sorted(paths, key=lambda x: (not x.startswith('/'), not x.startswith('http'), x)):
                print(f"        {path}")
    
    if not found_any:
        print("\n[-] No interesting paths found.")

    if js_urls:
        try:
            choice = input(f"\n[?] Download JS files? (y/N): ").strip().lower()
            if choice == 'y':
                deny_list = ['jquery', 'bootstrap', 'popper', 'fontawesome', 'react', 'vue', 'angular', 'moment', 'lodash', 'axios']
                exclude_choice = input("[?] Exclude 3rd party libraries? (y/N): ").strip().lower()
                
                flatten_choice = input("[?] Save all files in one folder? (y/N - 'y' for one folder, 'n' for original structure): ").strip().lower()
                flatten = True if flatten_choice == 'y' else False
                
                urls_to_download = js_urls
                if exclude_choice == 'y':
                    urls_to_download = [u for u in js_urls if not any(k in u.lower() for k in deny_list)]
                download_js_files(urls_to_download, flatten=flatten)
        except KeyboardInterrupt:
            print("\n[*] Operation cancelled.")

if __name__ == "__main__":
    main()