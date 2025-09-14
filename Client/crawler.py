import asyncio
import aiohttp
import requests
import time
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urldefrag
from aiolimiter import AsyncLimiter

MAX_CONCURRENCY = 10
RATE_LIMIT = 5
visited = set()
visited_lock = asyncio.Lock()
semaphore = asyncio.Semaphore(MAX_CONCURRENCY)
limiter = AsyncLimiter(max_rate=RATE_LIMIT, time_period=1)

start_url = "http://10.0.0.100:8000"

async def fetch_async(session, url):
    async with limiter:
        async with semaphore:
            try:
                start_time = time.perf_counter()
                async with session.get(url, timeout=10, headers={"Connection": "close"}) as resp:
                    latency = (time.perf_counter() - start_time) * 1000.0
                    html = await resp.text()
                    return html, resp.status, latency
            except Exception as e:
                print(f"Fetch error for {url}: {e}")
                return None, None, None

def format_status_line(url, status, latency):
    status_display = status if status is not None else "ERROR"
    lat_str = f"{latency:.2f} ms" if latency is not None else "N/A"
    return f"\nURL: {url}\nLatency: {lat_str}\t\tStatus: {status_display}"

async def crawl(session, url, base_url):
    url = urldefrag(url)[0]
    async with visited_lock:
        if url in visited:
            return
        visited.add(url)

    html, status, latency = await fetch_async(session, url)
    print(format_status_line(url, status, latency))

    if html is None:
        return

    soup = BeautifulSoup(html, 'html.parser')
    tasks = []
    for tag in soup.find_all("a", href=True):
        new_url = urljoin(base_url, tag['href'])
        if new_url == f"{start_url}/":
            new_url = new_url.rstrip('/')
        async with visited_lock:
            if new_url not in visited:
                tasks.append(crawl(session, new_url, base_url))
    await asyncio.gather(*tasks)

async def find_subsites(start_url):
    print("--- Discovering Subsites ---")
    # Set force_close=True to make each request use a new TCP stream
    connector = aiohttp.TCPConnector(force_close=False, limit=0, ttl_dns_cache=0)
    async with aiohttp.ClientSession(connector=connector) as session:
        await crawl(session, start_url, start_url)

def visit_subsites(urls_to_test):
    print("\n\n" + "="*40)
    print("--- Visiting Subsites Sequentially ---")
    print(f"Testing {len(urls_to_test)} URLs...")
    print("="*40)
    for url in urls_to_test:
        try:
            # No Session(): each call creates a new TCP connection.
            r = requests.get(
                url,
                timeout=10,
                headers={
                    "Connection": "close",
                    "Cache-Control": "no-cache",
                    "Pragma": "no-cache",
                    "allow_redirects": "False"
                },
            )
            latency = r.elapsed.total_seconds() * 1000.0
            print(format_status_line(url, r.status_code, latency))
        except requests.exceptions.RequestException as e:
            print(f"Fetch error for {url}: {e}")
            print(format_status_line(url, None, None))

if __name__ == "__main__":
    asyncio.run(find_subsites(start_url))
    visit_subsites(sorted(list(visited)))
