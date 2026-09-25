import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse
import re
import sys
import argparse
import os

def get_js_links(url, headers=None, proxies=None):
    """Fetches the URL and extracts all src attributes from script tags and inline script content."""
    if headers is None:
        headers = {}
    
    try:
        response = requests.get(url, timeout=10, verify=False, headers=headers, proxies=proxies)
        
        while response.status_code in [401, 403]:
            print(f"[-] Access denied: Status Code {response.status_code}")
            try:
                choice = input("[?] Do you want to add Authentication/Headers? (y/N): ").strip().lower()
                if choice != 'y':
                    break
                
                print("\n[?] Select Authentication Method:")
                print("    1. Authorization Header (Bearer / Basic)")
                print("    2. Cookie")
                print("    3. Custom Header (Key: Value)")
                print("    4. User-Agent")
                auth_choice = input("    Choice (1-4): ").strip()

                if auth_choice == '1':
                    print("    Select Auth Type:")
                    print("      a. Bearer")
                    print("      b. Basic")
                    token_type = input("      Choice (default Bearer): ").strip().lower()
                    auth_type = "Basic" if 'b' in token_type or token_type == '2' else "Bearer"
                    token = input(f"      Enter {auth_type} Token/Value: ").strip()
                    headers['Authorization'] = f"{auth_type} {token}"

                elif auth_choice == '2':
                    cookie_val = input("    Enter Cookie string (e.g. session=xyz; id=123): ").strip()
                    headers['Cookie'] = cookie_val

                elif auth_choice == '3':
                    header_name = input("    Enter Header Name (e.g. X-API-Key): ").strip()
                    header_val = input("    Enter Header Value: ").strip()
                    if header_name and header_val:
                        headers[header_name] = header_val

                elif auth_choice == '4':
                    ua_val = input("    Enter User-Agent string: ").strip()
                    if ua_val:
                        headers['User-Agent'] = ua_val

                print(f"[*] Retrying request with updated headers...")
                response = requests.get(url, timeout=10, verify=False, headers=headers, proxies=proxies)

            except KeyboardInterrupt:
                print("\n[*] Auth prompt cancelled.")
                return [], [], {}

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
            
        return list(set(js_links)), inline_scripts, headers
    except requests.exceptions.RequestException as e:
        print(f"[-] Error fetching base URL {url}: {e}")
        return [], [], {}

def is_garbage(s):
    """Check if the string is likely garbage/base64/obfuscated code or library schema."""
    if ': ' in s or ' expected' in s.lower():
        return True

    code_indicators = [
        '===', '==', '&&', '||', 'this.', 'const ', 'var ', 'let ', 'return ', 
        'function', '=>', 'new ', 'null:', 'undefined', 'typeof ', 'instanceof',
        'document.', 'window.', 'onClick', '{', '}', '[', ']', '(', ')'
    ]
    if any(ind in s for ind in code_indicators):
        return True

    if s.startswith('.') and not any(s.lower().endswith(ext) for ext in ['.php', '.js', '.css', '.html']):
        if s.count('.') > 1:
            return True

    if s.startswith((')', '(', '+', ',', ';', ':', '!', '=', '}', '{', '[', ']', '*')):
        return True
    if s.endswith(('(', '+', ',', ';', ':', '!', '=', '{', '[', '.', '?', '&')):
        return True

    if len(s) > 40 and '/' not in s and '.' not in s:
        return True
    
    if len(s) > 20 and re.match(r'^[a-zA-Z0-9+/=]{20,}$', s):
        if not any(ext in s.lower() for ext in ['.php', '.asp', '.jsp', '.json', '.xml', '.aspx', '.ashx']):
            return True
            
    garbage_patterns = [
        r'^styled-components', r'^@angular', r'^@babel', r'^moment/', r'^react',
        r'^[a-f0-9]{32}$',
        r'^\${.*}$',
        r'^text/', r'^image/', r'^application/',
        r'www\.w3\.org', r'ns\.adobe\.com', r'http://schemas\.', 
        r'^[A-Z0-9_/]{15,}$',
    ]
    for pattern in garbage_patterns:
        if re.search(pattern, s, re.IGNORECASE):
            return True
            
    return False

def extract_endpoints(content):
    """Uses advanced regex and context analysis to find potential API endpoints and paths."""
    endpoints = []
    
    context_regex = r"""(?:path|url|uri|endpoint|host|api|request|route|action|src|href)\s*[:=]\s*(?:"|'|`)([^"'`\s>]+)(?:"|'|`)"""
    context_matches = re.findall(context_regex, content, re.IGNORECASE)
    endpoints.extend(context_matches)

    string_regex = r"""(?:"|'|`)([^"'`]{3,})(?:"|'|`)"""
    all_strings = re.findall(string_regex, content)
    
    backend_extensions = ('.php', '.aspx', '.asp', '.jsp', '.json', '.action', '.do', '.ashx', '.asmx', '.cgi', '.js')
    path_indicators = ('/', './', '../', 'http://', 'https://', '//')

    for s in all_strings:
        s = s.strip()
        if is_garbage(s): continue

        if any(s.startswith(ind) for ind in path_indicators):
            if s.startswith('/') and len(s) > 1 and not re.match(r'^/[a-zA-Z0-9_\-\./\${}:?&=]+$', s):
                continue
            endpoints.append(s)
        elif any(ext in s.lower() for ext in backend_extensions):
            endpoints.append(s)
        elif '/' in s and re.match(r'^[a-z0-9_\-\./]+$', s): 
            if not s.lower().endswith(('.css', '.png', '.jpg', '.jpeg', '.svg', '.gif', '.woff', '.woff2', '.ttf', '.map')):
                endpoints.append(s)
        elif s.lower() in ('login', 'logout', 'signup', 'api', 'admin', 'status', 'auth', 'config', 'v1', 'v2'):
            endpoints.append(s)

    cleaned = []
    exclude_list = {
        'use strict', 'utf-8', 'object', 'string', 'number', 'boolean', 'undefined', 'null',
        'true', 'false', 'width', 'height', 'padding', 'margin', 'border', 'display', 'error'
    }
    
    for e in set(endpoints):
        check_e = re.sub(r'\${.*?}', 'VAR', e).strip("'\"` ").split('?')[0].split('#')[0]
        
        if not check_e or len(check_e) < 2: continue
        if check_e.lower() in exclude_list: continue
        if is_garbage(check_e): continue
        
        if '/' not in e and '.' not in e and e.lower() not in ('api', 'admin', 'login', 'status'):
            continue
            
        code_chars = sum(1 for c in e if c in '(){}[]!=<>:')
        if len(e) > 0 and (code_chars / len(e) > 0.15):
            continue

        cleaned.append(e)
        
    return list(set(cleaned))

def scan_js_file(js_url, headers=None, proxies=None):
    """Fetches a JS file and searches for paths inside strings."""
    try:
        response = requests.get(js_url, timeout=10, verify=False, headers=headers, proxies=proxies)
        response.raise_for_status()
        content = response.text
        return extract_endpoints(content)
    except requests.exceptions.RequestException as e:
        print(f"[-] Error fetching JS {js_url}: {e}")
        return []

def download_js_files(js_urls, headers=None, flatten=False, proxies=None):
    """Downloads the list of JS files, optionally preserving directory structure."""
    print(f"\n[*] Preparing to download {len(js_urls)} files...")
    
    base_dir = "downloaded_js"
    if not os.path.exists(base_dir):
        os.makedirs(base_dir)

    for url in js_urls:
        try:
            parsed_url = urlparse(url)
            
            if flatten:
                filename = os.path.basename(parsed_url.path)
                if not filename or not filename.endswith('.js'):
                    filename = f"script_{abs(hash(url))}.js"
                
                local_path = os.path.join(base_dir, filename)
                
                if os.path.exists(local_path):
                     name, ext = os.path.splitext(filename)
                     local_path = os.path.join(base_dir, f"{name}_{str(abs(hash(url)))[:6]}{ext}")
            else:
                url_path = parsed_url.path.lstrip('/')
                local_path = os.path.join(base_dir, url_path)
                
                if not url_path or url_path.endswith('/'):
                     local_path = os.path.join(local_path, f"script_{abs(hash(url))}.js")

                os.makedirs(os.path.dirname(local_path), exist_ok=True)

            print(f"  -> Downloading: {url} -> {local_path} ...", end=" ")
            response = requests.get(url, timeout=10, verify=False, headers=headers, proxies=proxies)
            response.raise_for_status()
            with open(local_path, 'wb') as f:
                f.write(response.content)
            print("Done")
        except Exception as e:
            print(f"Failed ({e})")

def load_urls_from_file(file_path):
    """Reads a list of URLs from a text file."""
    urls = []
    if os.path.exists(file_path):
        with open(file_path, 'r', encoding='utf-8') as f:
            for line in f:
                url = line.strip()
                if url and not url.startswith('#'):
                    urls.append(url)
        print(f"[*] Loaded {len(urls)} URL(s) from {file_path}")
    else:
        print(f"[-] File not found: {file_path}")
    return urls

def main():
    parser = argparse.ArgumentParser(description="Clean & Precise JS Path Extractor")
    parser.add_argument("url", help="Target URL to scan")
    parser.add_argument("-p", "--proxy", help="Proxy URL (e.g., http://127.0.0.1:8080)", default=None)
    parser.add_argument("-ua", "--user-agent", help="Custom User-Agent string", default=None)
    parser.add_argument("-f", "--file", help="Path to text file containing JS URLs (e.g., link.txt)", default=None)
    args = parser.parse_args()

    target_url = args.url
    proxies = None
    if args.proxy:
        proxies = {
            "http": args.proxy,
            "https": args.proxy
        }
        print(f"[*] Using proxy: {args.proxy}")

    initial_headers = {}
    if args.user_agent:
        initial_headers['User-Agent'] = args.user_agent
        print(f"[*] Using User-Agent: {args.user_agent}")

    print(f"[*] Scanning target: {target_url}")
    
    requests.packages.urllib3.disable_warnings(requests.packages.urllib3.exceptions.InsecureRequestWarning)
    js_urls, inline_scripts, auth_headers = get_js_links(target_url, headers=initial_headers, proxies=proxies)
    
    # อ่านไฟล์ URL เพิ่มเติมกรณีระบุออปชัน -f หรือ --file
    file_js_urls = []
    if args.file:
        file_js_urls = load_urls_from_file(args.file)

    if not js_urls and not inline_scripts and not file_js_urls:
        print("[-] No JavaScript found.")
        return

    print(f"[*] Found {len(js_urls)} initial JS files and {len(inline_scripts)} inline scripts.")

    all_found = {}
    nested_js_urls = set()

    for js_url in js_urls:
        print(f"  -> Checking: {js_url}")
        found_paths = scan_js_file(js_url, headers=auth_headers, proxies=proxies)
        if found_paths:
            all_found[js_url] = found_paths
            for path in found_paths:
                clean_path = path.split('?')[0].split('#')[0]
                if clean_path.lower().endswith('.js'):
                    full_js_url = urljoin(js_url, path)
                    nested_js_urls.add(full_js_url)

    if inline_scripts:
        print(f"  -> Checking inline scripts...")
        for i, script in enumerate(inline_scripts):
            found_paths = extract_endpoints(script)
            if found_paths:
                all_found[f"Inline Script #{i+1}"] = found_paths
                for path in found_paths:
                    clean_path = path.split('?')[0].split('#')[0]
                    if clean_path.lower().endswith('.js'):
                        full_js_url = urljoin(target_url, path)
                        nested_js_urls.add(full_js_url)

    found_any = False
    for source, paths in all_found.items():
        if paths:
            found_any = True
            print(f"\n[+] {len(paths)} PATHS FOUND in {source}:")
            for path in sorted(paths, key=lambda x: (not x.startswith('/'), not x.startswith('http'), x)):
                print(f"        {path}")
    
    if not found_any:
        print("\n[-] No interesting paths found.")

    # รวมไฟล์ JS ทั้งหมด (จากหน้าเว็บ + จากสคริปต์ซ้อน + จากไฟล์ link.txt)
    total_js_to_download = set(js_urls).union(nested_js_urls).union(file_js_urls)

    if nested_js_urls:
        print(f"\n[+] Discovered {len(nested_js_urls)} additional JS file(s) inside scripts:")
        for nj in sorted(nested_js_urls):
            print(f"        {nj}")

    if total_js_to_download:
        try:
            choice = input(f"\n[?] Download all discovered JS files ({len(total_js_to_download)} files)? (y/N): ").strip().lower()
            if choice == 'y':
                deny_list = ['jquery', 'bootstrap', 'popper', 'fontawesome', 'react', 'vue', 'angular', 'moment', 'lodash', 'axios']
                exclude_choice = input("[?] Exclude 3rd party libraries? (y/N): ").strip().lower()
                
                flatten_choice = input("[?] Save all files in one folder? (y/N - 'y' for one folder, 'n' for original structure): ").strip().lower()
                flatten = True if flatten_choice == 'y' else False
                
                urls_to_download = list(total_js_to_download)
                if exclude_choice == 'y':
                    urls_to_download = [u for u in urls_to_download if not any(k in u.lower() for k in deny_list)]
                download_js_files(urls_to_download, headers=auth_headers, flatten=flatten, proxies=proxies)
        except KeyboardInterrupt:
            print("\n[*] Operation cancelled.")

if __name__ == "__main__":
    main()
