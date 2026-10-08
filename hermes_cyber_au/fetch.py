"""Allowlisted HTTPS fetch. TLS is verified. Redirects must stay on the allowlist."""

from __future__ import annotations

import json
import socket
import ssl
import urllib.error
import urllib.request
from dataclasses import dataclass
from urllib.parse import urljoin, urlparse

# Some agency sites black-hole IPv6 from this network. Pin lookups to IPv4
# so a dead AAAA record does not burn the timeout on every page.
_ORIG_GETADDRINFO = socket.getaddrinfo


def _ipv4_getaddrinfo(host, port, family=0, type=0, proto=0, flags=0):
    return _ORIG_GETADDRINFO(host, port, socket.AF_INET, type, proto, flags)

from .common import sha256_bytes

# Keep this short. The long parenthetical form makes www.cyber.gov.au stall the read.
USER_AGENT = "hermes-cyber-au/0.1"
MAX_BYTES = 12_000_000
TIMEOUT = 40


class FetchError(Exception):
    def __init__(self, code: str, detail: str = ""):
        super().__init__(detail or code)
        self.code = code
        self.detail = detail or code


@dataclass
class FetchResult:
    url: str
    final_url: str
    status: int
    body: bytes
    content_type: str
    sha256: str

    def text(self) -> str:
        return self.body.decode("utf-8", errors="replace")

    def json(self) -> object:
        return json.loads(self.body.decode("utf-8"))


def _host_ok(url: str, hosts: set[str], path_prefixes: tuple[str, ...]) -> None:
    parsed = urlparse(url)
    if parsed.scheme != "https":
        raise FetchError("tls_required", url)
    host = (parsed.hostname or "").lower()
    if host not in hosts:
        raise FetchError("host_not_allowlisted", host or url)
    if path_prefixes and not any(parsed.path.startswith(prefix) for prefix in path_prefixes):
        raise FetchError("path_not_allowlisted", parsed.path)


class _GuardRedirect(urllib.request.HTTPRedirectHandler):
    def __init__(self, hosts: set[str], path_prefixes: tuple[str, ...]):
        super().__init__()
        self.hosts = hosts
        self.path_prefixes = path_prefixes

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        # GitHub raw and agency sites may redirect. The new URL is checked
        # against the same allowlist. A login wall or an off-list host stops here.
        _host_ok(newurl, self.hosts, ())
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def fetch_url(
    url: str,
    hosts: set[str],
    path_prefixes: tuple[str, ...] = (),
    *,
    timeout: int = TIMEOUT,
    max_bytes: int = MAX_BYTES,
    headers: dict[str, str] | None = None,
) -> FetchResult:
    _host_ok(url, hosts, path_prefixes)
    context = ssl.create_default_context()
    handlers = [_GuardRedirect(hosts, path_prefixes), urllib.request.HTTPSHandler(context=context)]
    opener = urllib.request.build_opener(*handlers)
    sent = {"User-Agent": USER_AGENT, "Accept": "*/*"}
    if headers:
        sent.update(headers)
    request = urllib.request.Request(url, headers=sent)
    socket.getaddrinfo = _ipv4_getaddrinfo
    try:
        try:
            with opener.open(request, timeout=timeout) as response:
                final_url = response.geturl()
                _host_ok(final_url, hosts, ())
                status = getattr(response, "status", 200)
                content_type = response.headers.get("Content-Type", "")
                body = response.read(max_bytes + 1)
        except FetchError:
            raise
        except urllib.error.HTTPError as exc:
            raise FetchError(f"http_{exc.code}", url) from exc
        except urllib.error.URLError as exc:
            raise FetchError("transport", f"{url}: {exc.reason}") from exc
        except (TimeoutError, OSError) as exc:
            raise FetchError("transport", f"{url}: {exc}") from exc
    finally:
        socket.getaddrinfo = _ORIG_GETADDRINFO
    if len(body) > max_bytes:
        raise FetchError("too_large", url)
    if not body:
        raise FetchError("empty", url)
    return FetchResult(
        url=url,
        final_url=final_url,
        status=status,
        body=body,
        content_type=content_type,
        sha256=sha256_bytes(body),
    )


def github_commit(repo: str, ref: str, hosts: set[str]) -> str:
    """Resolve one git ref to a full commit SHA via the GitHub API."""
    if repo.count("/") != 1:
        raise FetchError("bad_repo", repo)
    safe_ref = ref.removeprefix("refs/heads/")
    url = f"https://api.github.com/repos/{repo}/commits/{safe_ref}"
    result = fetch_url(url, hosts | {"api.github.com"}, (f"/repos/{repo}/",))
    payload = result.json()
    if not isinstance(payload, dict) or not isinstance(payload.get("sha"), str):
        raise FetchError("bad_commit_payload", repo)
    sha = payload["sha"]
    if len(sha) != 40 or any(ch not in "0123456789abcdef" for ch in sha):
        raise FetchError("bad_sha", sha)
    return sha


def raw_github(repo: str, sha: str, path: str, hosts: set[str]) -> FetchResult:
    url = f"https://raw.githubusercontent.com/{repo}/{sha}/{path}"
    prefix = f"/{repo}/"
    return fetch_url(url, hosts | {"raw.githubusercontent.com"}, (prefix,))


def abs_link(base: str, href: str) -> str:
    return urljoin(base, href)
