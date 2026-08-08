"""Single centrally configured outbound HTTP client for Odoo connectivity.

All adapters must use this client factory. It enforces:
- follow_redirects=False (redirects are never followed)
- trust_env=False (no environment proxy trust)
- TLS certificate verification always ON — there is deliberately NO option
  to disable it
- strict connect/read/write/pool timeouts
- identifiable User-Agent
- probe response size limit (checked by callers via read_limited)
"""

import httpx

USER_AGENT = "Modeem-AI-Platform/0.1"
MAX_PROBE_RESPONSE_BYTES = 1_000_000  # 1 MB is far beyond any metadata probe

_TIMEOUT = httpx.Timeout(connect=5.0, read=10.0, write=5.0, pool=5.0)


def build_client() -> httpx.Client:
    return httpx.Client(
        follow_redirects=False,
        trust_env=False,
        verify=True,  # never configurable off
        timeout=_TIMEOUT,
        headers={"User-Agent": USER_AGENT},
    )


def check_response_size(response: httpx.Response) -> None:
    from .errors import ConnectorError

    if len(response.content) > MAX_PROBE_RESPONSE_BYTES:
        raise ConnectorError("unsupported_response", "probe response too large")
