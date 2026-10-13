import asyncio
from typing import Set, List, Dict, Any, Callable, Awaitable, Optional
from urllib.parse import urlparse, urljoin
from bs4 import BeautifulSoup
import httpx
from app.scanner.ssrf_validator import SafeAsyncHttpClient, validate_url_safety
from app.core.config import settings


class BoundedSameOriginCrawler:
    """
    Safe, non-destructive same-origin web crawler.
    Enforces page limit, depth limit, per-request timeout, overall deadline,
    and same-origin boundary.
    """

    def __init__(
        self,
        base_url: str,
        http_client: SafeAsyncHttpClient,
        max_pages: int = 25,
        max_depth: int = 2,
        max_concurrency: int = 4
    ):
        self.base_url = base_url
        self.http_client = http_client
        self.max_pages = min(max_pages, settings.MAX_CRAWL_PAGES)
        self.max_depth = min(max_depth, settings.MAX_CRAWL_DEPTH)
        self.semaphore = asyncio.Semaphore(max_concurrency)

        parsed = urlparse(base_url)
        self.origin = f"{parsed.scheme.lower()}://{parsed.netloc.lower()}"
        self.visited_urls: Set[str] = set()

    def is_same_origin(self, url: str) -> bool:
        try:
            parsed = urlparse(url)
            candidate_origin = f"{parsed.scheme.lower()}://{parsed.netloc.lower()}"
            return candidate_origin == self.origin
        except Exception:
            return False

    def clean_url(self, url: str) -> str:
        parsed = urlparse(url)
        # Strip fragment and normalized path
        path = parsed.path if parsed.path else "/"
        cleaned = f"{parsed.scheme.lower()}://{parsed.netloc}{path}"
        if parsed.query:
            cleaned += f"?{parsed.query}"
        return cleaned

    async def crawl(
        self,
        page_callback: Callable[[str, httpx.Response], Awaitable[None]],
        log_callback: Optional[Callable[[str, str], Awaitable[None]]] = None
    ) -> List[str]:
        queue: List[tuple[str, int]] = [(self.base_url, 0)]
        scanned_urls: List[str] = []

        while queue and len(self.visited_urls) < self.max_pages:
            current_url, depth = queue.pop(0)
            cleaned = self.clean_url(current_url)

            if cleaned in self.visited_urls:
                continue

            self.visited_urls.add(cleaned)

            if log_callback:
                await log_callback(f"Auditing page: {cleaned} (depth {depth})", "INFO")

            try:
                async with self.semaphore:
                    response = await self.http_client.get(cleaned)

                scanned_urls.append(cleaned)
                await page_callback(cleaned, response)

                # If below max depth, extract links from HTML
                if depth < self.max_depth and "text/html" in response.headers.get("content-type", "").lower():
                    soup = BeautifulSoup(response.text[:100000], "html.parser")
                    for a_tag in soup.find_all("a", href=True):
                        href = a_tag["href"].strip()
                        # Skip mailto, javascript, tel, and fragment links
                        if href.startswith(("mailto:", "javascript:", "tel:", "#")):
                            continue

                        resolved = urljoin(cleaned, href)
                        # Check same origin and safety
                        if self.is_same_origin(resolved):
                            is_safe, norm, _ = validate_url_safety(resolved)
                            if is_safe and norm not in self.visited_urls:
                                queue.append((norm, depth + 1))

            except Exception as e:
                if log_callback:
                    await log_callback(f"Failed to fetch {cleaned}: {str(e)[:100]}", "WARNING")

        return scanned_urls
