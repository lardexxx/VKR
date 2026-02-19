from __future__ import annotations

from collections import deque
from dataclasses import dataclass
from typing import Iterable
from urllib.parse import parse_qsl, urldefrag, urljoin, urlparse

import requests
from bs4 import BeautifulSoup
from bs4.element import Tag


CSRF_KEYWORDS = ("csrf", "xsrf", "_token", "authenticity_token", "csrfmiddlewaretoken", "__requestverificationtoken")


@dataclass(frozen=True)
class Target:
    url: str
    method: str
    injectable_params: tuple[str, ...] = ()
    fixed_params: tuple[tuple[str, str], ...] = ()
    source_url: str = ""
    form_html: str | None = None
    kind: str = "form"  # form | query
    enctype: str | None = None
    csrf_param_names: tuple[str, ...] = ()
    param_types: tuple[tuple[str, str], ...] = ()
    submit_options: tuple[tuple[str, str], ...] = ()


def _looks_like_csrf(name: str) -> bool:
    name_l = name.lower()
    return any(keyword in name_l for keyword in CSRF_KEYWORDS)


def _is_disabled(control: Tag) -> bool:
    if control.has_attr("disabled"):
        return True

    for fieldset in control.find_parents("fieldset"):
        if not fieldset.has_attr("disabled"):
            continue

        legends = fieldset.find_all("legend", recursive=False)
        if legends and legends[0] in control.parents:
            continue
        return True

    return False


def _option_value(option: Tag) -> str:
    value = option.get("value")
    if value is None:
        value = option.get_text(strip=True)
    return value or ""


def extract_get_target(url: str, source_url: str) -> Target | None:
    parsed = urlparse(url)
    if not parsed.query:
        return None

    params = parse_qsl(parsed.query, keep_blank_values=True)
    if not params:
        return None

    endpoint = parsed._replace(query="").geturl()

    injectable = sorted({key.strip() for key, _ in params if key and key.strip()})
    fixed = [(key.strip(), value) for key, value in params if key and key.strip()]

    return Target(
        url=endpoint,
        method="GET",
        injectable_params=tuple(injectable),
        fixed_params=tuple(fixed),
        source_url=source_url,
        kind="query",
        param_types=tuple((name, "query") for name in injectable),
    )


def extract_forms(page_url: str, html: str, include_submit: bool = False) -> list[Target]:
    soup = BeautifulSoup(html, "html.parser")
    targets: list[Target] = []

    for form in soup.find_all("form"):
        method = (form.get("method") or "GET").strip().upper()
        if method not in {"GET", "POST"}:
            method = "GET"

        action = form.get("action") or page_url
        action_url = urljoin(page_url, action)
        enctype = (form.get("enctype") or "application/x-www-form-urlencoded").strip().lower()

        injectable: set[str] = set()
        fixed: list[tuple[str, str]] = []
        csrf_names: set[str] = set()
        param_types: dict[str, str] = {}
        submit_candidates: list[tuple[str, str]] = []

        controls: Iterable[Tag] = form.find_all(["input", "textarea", "select", "button"])
        for control in controls:
            if _is_disabled(control):
                continue

            tag_name = control.name
            name = control.get("name")
            if not name:
                continue
            name = name.strip()
            if not name:
                continue

            if _looks_like_csrf(name):
                csrf_names.add(name)

            if tag_name == "input":
                input_type = (control.get("type") or "text").lower()
                value = control.get("value")
                param_types.setdefault(name, input_type)

                if input_type == "hidden":
                    fixed.append((name, value or ""))
                elif input_type in {"submit", "button"}:
                    submit_candidates.append((name, value or ""))
                elif input_type == "image":
                    submit_candidates.append((f"{name}.x", "0"))
                    submit_candidates.append((f"{name}.y", "0"))
                elif input_type == "radio":
                    injectable.add(name)
                    if control.has_attr("checked"):
                        fixed.append((name, value if value is not None else "on"))
                elif input_type == "checkbox":
                    injectable.add(name)
                    if control.has_attr("checked"):
                        fixed.append((name, value if value else "on"))
                elif input_type in {"reset", "file"}:
                    continue
                else:
                    injectable.add(name)

            elif tag_name == "textarea":
                param_types.setdefault(name, "textarea")
                injectable.add(name)
                fixed.append((name, control.text or ""))

            elif tag_name == "select":
                param_types.setdefault(name, "select")
                injectable.add(name)
                options = control.find_all("option")
                if not options:
                    continue

                selected = [option for option in options if option.has_attr("selected")]
                is_multiple = control.has_attr("multiple")
                if is_multiple:
                    for option in selected:
                        fixed.append((name, _option_value(option)))
                else:
                    chosen = selected[0] if selected else options[0]
                    fixed.append((name, _option_value(chosen)))

            elif tag_name == "button":
                button_type = (control.get("type") or "submit").lower()
                param_types.setdefault(name, f"button:{button_type}")
                if button_type in {"submit", "button"}:
                    submit_candidates.append((name, control.get("value") or ""))

        if include_submit and submit_candidates:
            fixed.append(submit_candidates[0])

        targets.append(
            Target(
                url=action_url,
                method=method,
                injectable_params=tuple(sorted(injectable)),
                fixed_params=tuple(fixed),
                source_url=page_url,
                form_html=str(form),
                kind="form",
                enctype=enctype,
                csrf_param_names=tuple(sorted(csrf_names)),
                param_types=tuple(sorted(param_types.items())),
                submit_options=tuple(submit_candidates),
            )
        )

    return targets


def extract_page_targets(page_url: str, html: str, include_submit: bool = False) -> list[Target]:
    targets = extract_forms(page_url=page_url, html=html, include_submit=include_submit)
    query_target = extract_get_target(page_url, source_url=page_url)
    if query_target is not None:
        targets.append(query_target)
    return targets


def is_good_link(href: str | None) -> bool:
    if not href:
        return False
    href_l = href.strip().lower()
    if not href_l:
        return False
    if href_l.startswith("#"):
        return False
    if href_l.startswith(("mailto:", "tel:", "javascript:", "data:")):
        return False
    return True


def crawl_links(base_url: str, max_pages: int = 20) -> list[str]:
    session = requests.Session()
    queue = deque([base_url])
    visited: set[str] = set()
    base_host = urlparse(base_url).netloc

    while queue and len(visited) < max_pages:
        url = queue.popleft()
        if url in visited:
            continue
        visited.add(url)

        try:
            response = session.get(url, timeout=10)
        except requests.RequestException:
            continue

        content_type = response.headers.get("Content-Type", "").lower()
        if "text/html" not in content_type:
            continue

        soup = BeautifulSoup(response.text, "html.parser")
        for anchor in soup.find_all("a"):
            href = anchor.get("href")
            if not is_good_link(href):
                continue

            abs_url, _ = urldefrag(urljoin(url, href))
            if urlparse(abs_url).netloc != base_host:
                continue
            if abs_url not in visited:
                queue.append(abs_url)

    return list(visited)


def crawl_targets(base_url: str, max_pages: int = 20, include_submit: bool = False) -> tuple[list[str], list[Target]]:
    session = requests.Session()
    queue = deque([base_url])
    visited: set[str] = set()
    all_targets: list[Target] = []
    seen_target_keys: set[
        tuple[
            str,
            str,
            tuple[str, ...],
            tuple[tuple[str, str], ...],
            tuple[tuple[str, str], ...],
            tuple[str, ...],
            str | None,
            str,
        ]
    ] = set()
    base_host = urlparse(base_url).netloc

    while queue and len(visited) < max_pages:
        url = queue.popleft()
        if url in visited:
            continue
        visited.add(url)

        try:
            response = session.get(url, timeout=10)
        except requests.RequestException:
            continue

        content_type = response.headers.get("Content-Type", "").lower()
        if "text/html" not in content_type:
            continue

        html = response.text
        page_targets = extract_page_targets(url, html, include_submit=include_submit)
        for target in page_targets:
            key = (
                target.method,
                target.url,
                target.injectable_params,
                target.fixed_params,
                target.submit_options,
                target.csrf_param_names,
                target.enctype,
                target.kind,
            )
            if key not in seen_target_keys:
                seen_target_keys.add(key)
                all_targets.append(target)

        soup = BeautifulSoup(html, "html.parser")
        for anchor in soup.find_all("a"):
            href = anchor.get("href")
            if not is_good_link(href):
                continue

            abs_url, _ = urldefrag(urljoin(url, href))
            if urlparse(abs_url).netloc != base_host:
                continue
            if abs_url not in visited:
                queue.append(abs_url)

    return list(visited), all_targets
