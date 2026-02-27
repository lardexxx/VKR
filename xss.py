from __future__ import annotations

import html
from dataclasses import dataclass

from crawler_my import Target, crawl_targets
from payloads import classify_xss_context, get_context_payloads, get_probe_payloads
from request import RequestConfig, create_session, execute_target


@dataclass
class XSSFinding:
    finding_type: str
    url: str
    method: str
    param: str
    context: str
    payload: str
    source_url: str
    status_code: int


def is_reflected_unescaped(payload: str, response_text: str) -> bool:
    """
    Basic heuristic:
    - payload is reflected as-is;
    - escaped payload is not the only reflected form.
    """
    escaped = html.escape(payload)
    return payload in response_text and escaped not in response_text


def param_type_map(target: Target) -> dict[str, str]:
    return {name: ptype for name, ptype in target.param_types}


def payloads_for_param(target: Target, param: str) -> tuple[str, tuple[str, ...]]:
    ptypes = param_type_map(target)
    context = classify_xss_context(ptypes.get(param))
    return context, get_context_payloads(context)


def scan_xss(
    targets: list[Target],
    request_config: RequestConfig | None = None,
    default_injectable_value: str = "test",
) -> list[XSSFinding]:
    config = request_config or RequestConfig()
    session = create_session(config)
    findings: list[XSSFinding] = []

    for target in targets:
        if not target.injectable_params:
            continue

        for param in target.injectable_params:
            probe_hit = False
            for payload in get_probe_payloads():
                result = execute_target(
                    session=session,
                    target=target,
                    tested_param=param,
                    payload=payload,
                    config=config,
                    default_injectable_value=default_injectable_value,
                )
                if not result.success or result.response is None:
                    continue

                response = result.response
                if is_reflected_unescaped(payload, response.text):
                    probe_hit = True
                    break

            if not probe_hit:
                continue

            context, context_payloads = payloads_for_param(target, param)
            for payload in context_payloads:
                result = execute_target(
                    session=session,
                    target=target,
                    tested_param=param,
                    payload=payload,
                    config=config,
                    default_injectable_value=default_injectable_value,
                )
                if not result.success or result.response is None:
                    continue

                response = result.response
                if is_reflected_unescaped(payload, response.text):
                    findings.append(
                        XSSFinding(
                            finding_type="Reflected XSS",
                            url=target.url,
                            method=target.method,
                            param=param,
                            context=context,
                            payload=payload,
                            source_url=target.source_url,
                            status_code=response.status_code,
                        )
                    )
                    break

    return findings


def run_xss_scan(base_url: str, max_pages: int = 20, include_submit: bool = True) -> list[XSSFinding]:
    targets = crawl_targets(base_url=base_url, max_pages=max_pages, include_submit=include_submit)
    return scan_xss(targets=targets)


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="Simple reflected XSS scanner")
    parser.add_argument("base_url", help="Start URL for crawling")
    parser.add_argument("--max-pages", type=int, default=20, help="Maximum pages to crawl")
    parser.add_argument("--no-submit", action="store_true", help="Do not include submit button variants")

    args = parser.parse_args()

    results = run_xss_scan(
        base_url=args.base_url,
        max_pages=args.max_pages,
        include_submit=not args.no_submit,
    )

    if not results:
        print("No reflected XSS findings")
    else:
        print(f"Found {len(results)} potential reflected XSS issues")
        for finding in results:
            print(
                f"[{finding.finding_type}] {finding.method} {finding.url} "
                f"param={finding.param} context={finding.context} status={finding.status_code}"
            )
