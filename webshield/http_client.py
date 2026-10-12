import time
import requests
from urllib.parse import urlparse
from . import config

class HttpClient:
    def __init__(self, allowed_hosts=None):
        self.allowed_hosts = allowed_hosts or config.ALLOWED_HOSTS
        self.session = requests.Session()
        self.session.headers.update({"User-Agent": config.USER_AGENT})
        self.last_request = 0

    def _check_host(self, url):
        host = urlparse(url).hostname
        if host not in self.allowed_hosts:
            raise ValueError(f"Host not allowed: {host}")

    def _rate_limit(self):
        elapsed = time.time() - self.last_request
        min_interval = 1.0 / config.MAX_REQUESTS_PER_SECOND
        if elapsed < min_interval:
            time.sleep(min_interval - elapsed)
        self.last_request = time.time()

    def get(self, url, **kwargs):
        self._check_host(url)
        self._rate_limit()
        return self.session.get(url, timeout=config.REQUEST_TIMEOUT, **kwargs)

    def post(self, url, **kwargs):
        self._check_host(url)
        self._rate_limit()
        return self.session.post(url, timeout=config.REQUEST_TIMEOUT, **kwargs)
