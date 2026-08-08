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


def post_limited(
    client: httpx.Client,
    url: str,
    *,
    content: bytes | None = None,
    json: dict | list | None = None,
    headers: dict[str, str] | None = None,
) -> httpx.Response:
    """POST and read the response as a stream, enforcing the byte cap while
    iterating chunks. The connection is aborted as soon as the cap is
    exceeded — the body is never fully buffered first."""
    from .errors import ConnectorError

    with client.stream(
        "POST", url, content=content, json=json, headers=headers
    ) as response:
        declared = response.headers.get("Content-Length")
        if (
            declared is not None
            and declared.isdigit()
            and int(declared) > MAX_PROBE_RESPONSE_BYTES
        ):
            raise ConnectorError("unsupported_response", "probe response too large")
        chunks: list[bytes] = []
        total = 0
        for chunk in response.iter_bytes():
            total += len(chunk)
            if total > MAX_PROBE_RESPONSE_BYTES:
                raise ConnectorError(
                    "unsupported_response", "probe response too large"
                )
            chunks.append(chunk)
    # Attach the size-capped body so callers can use response.content/.json().
    response._content = b"".join(chunks)
    return response
