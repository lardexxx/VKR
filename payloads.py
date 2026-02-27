from __future__ import annotations

# Lightweight payload catalog for reflected XSS checks.
# Goal: keep scan speed reasonable while covering major contexts.
XSS_PAYLOADS: dict[str, tuple[str, ...]] = {
    "probe": (
        "xssprobe123",
        "xss'\"<>123",
    ),
    "html": (
        "<script>alert(1337)</script>",
        "<img src=x onerror=alert(1337)>",
    ),
    "attr": (
        "\" onmouseover=\"alert(1337)",
        "' autofocus onfocus=alert(1337) x='",
    ),
    "js": (
        "';alert(1337);//",
        "\";alert(1337);//",
    ),
}


def normalize_param_type(param_type: str | None) -> str:
    if not param_type:
        return "unknown"
    return param_type.strip().lower()


def classify_xss_context(param_type: str | None) -> str:
    """
    Map crawler field type to the likely sink context.
    This is heuristic and intentionally conservative.
    """
    ptype = normalize_param_type(param_type)

    if ptype in {"query"}:
        return "html"
    if ptype in {"textarea", "text", "search", "email", "url", "tel", "password"}:
        return "html"
    if ptype in {"hidden", "select"}:
        return "attr"
    if ptype in {"number", "range", "date", "datetime-local", "time", "month", "week"}:
        return "js"
    if ptype.startswith("button:"):
        return "attr"
    return "html"


def get_probe_payloads() -> tuple[str, ...]:
    return XSS_PAYLOADS["probe"]


def get_context_payloads(context: str) -> tuple[str, ...]:
    return XSS_PAYLOADS.get(context, XSS_PAYLOADS["html"])

