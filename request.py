from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Any

import requests

from crawler_my import Target

DEFAULT_TIMEOUT = 10
DEFAULT_USER_AGENT = "vkr-scanner/0.1 (+educational)"


@dataclass
class RequestConfig:
    timeout: int = DEFAULT_TIMEOUT
    verify_ssl: bool = True
    allow_redirects: bool = True
    max_redirects: int = 10
    retries: int = 1
    retry_delay_sec: float = 0.35
    retry_on_status: tuple[int, ...] = (429, 500, 502, 503, 504)
    headers: dict[str, str] = field(default_factory=dict)
    proxies: dict[str, str] | None = None


@dataclass
class ExecutionResult:
    success: bool
    response: requests.Response | None
    error: str | None
    attempts: int
    method: str
    url: str
    tested_param: str
    payload: str


def create_session(config: RequestConfig | None = None) -> requests.Session:
    cfg = config or RequestConfig()
    session = requests.Session()
    session.max_redirects = cfg.max_redirects
    session.headers.update({"User-Agent": DEFAULT_USER_AGENT})
    if cfg.headers:
        session.headers.update(cfg.headers)
    if cfg.proxies:
        session.proxies.update(cfg.proxies)
    return session


def build_request_pairs(
    target: Target,
    tested_param: str,
    payload: str,
    default_injectable_value: str = "",
) -> list[tuple[str, str]]:
    """
    Build request pairs while preserving baseline form/query values.

    Rules:
    - keep all fixed_params as baseline (including duplicates);
    - replace value of tested tested_param with payload in existing pairs;
    - if a target injectable param is missing in baseline, append one value:
      payload for tested_param, default_injectable_value for the rest.
    """
    pairs: list[tuple[str, str]] = []
    existing_counts: dict[str, int] = {}

    for key, value in target.fixed_params:
        if key == tested_param:
            pairs.append((key, payload))
        else:
            pairs.append((key, value))
        existing_counts[key] = existing_counts.get(key, 0) + 1

    for key in target.injectable_params:
        if existing_counts.get(key, 0) > 0:
            continue
        if key == tested_param:
            pairs.append((key, payload))
        else:
            pairs.append((key, default_injectable_value))
        existing_counts[key] = existing_counts.get(key, 0) + 1

    if tested_param and existing_counts.get(tested_param, 0) == 0 and tested_param not in target.injectable_params:
        pairs.append((tested_param, payload))

    return pairs


def build_request_kwargs(target: Target, pairs: list[tuple[str, str]]) -> dict[str, Any]:
    method = target.method.upper()
    if method == "GET":
        return {"params": pairs}

    enctype = (target.enctype or "application/x-www-form-urlencoded").lower()
    if enctype.startswith("multipart/form-data"):
        return {"files": [(name, (None, value)) for name, value in pairs]}
    return {"data": pairs}


def _send_once(
    session: requests.Session,
    target: Target,
    request_kwargs: dict[str, Any],
    config: RequestConfig,
) -> requests.Response:
    return session.request(
        method=target.method.upper(),
        url=target.url,
        timeout=config.timeout,
        allow_redirects=config.allow_redirects,
        verify=config.verify_ssl,
        **request_kwargs,
    )


def execute_target(
    session: requests.Session,
    target: Target,
    tested_param: str,
    payload: str,
    config: RequestConfig | None = None,
    default_injectable_value: str = "",
) -> ExecutionResult:
    """
    Execute one target request with payload in a single parameter.
    Returns structured status so detectors can handle errors consistently.
    """
    cfg = config or RequestConfig()
    pairs = build_request_pairs(
        target=target,
        tested_param=tested_param,
        payload=payload,
        default_injectable_value=default_injectable_value,
    )
    request_kwargs = build_request_kwargs(target=target, pairs=pairs)

    max_attempts = max(1, cfg.retries + 1)
    last_error: str | None = None

    for attempt in range(1, max_attempts + 1):
        try:
            response = _send_once(
                session=session,
                target=target,
                request_kwargs=request_kwargs,
                config=cfg,
            )
            if response.status_code in cfg.retry_on_status and attempt < max_attempts:
                time.sleep(cfg.retry_delay_sec)
                continue
            return ExecutionResult(
                success=True,
                response=response,
                error=None,
                attempts=attempt,
                method=target.method.upper(),
                url=target.url,
                tested_param=tested_param,
                payload=payload,
            )
        except requests.RequestException as exc:
            last_error = str(exc)
            if attempt < max_attempts:
                time.sleep(cfg.retry_delay_sec)
                continue

    return ExecutionResult(
        success=False,
        response=None,
        error=last_error or "unknown request error",
        attempts=max_attempts,
        method=target.method.upper(),
        url=target.url,
        tested_param=tested_param,
        payload=payload,
    )


def execute_target_response(
    session: requests.Session,
    target: Target,
    tested_param: str,
    payload: str,
    config: RequestConfig | None = None,
    default_injectable_value: str = "",
) -> requests.Response | None:
    """
    Compatibility helper for code that only needs Response|None.
    """
    result = execute_target(
        session=session,
        target=target,
        tested_param=tested_param,
        payload=payload,
        config=config,
        default_injectable_value=default_injectable_value,
    )
    return result.response
