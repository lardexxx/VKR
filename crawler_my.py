from collections import deque
from urllib.parse import urljoin, urlparse, urldefrag, parse_qsl
import requests
from bs4 import BeautifulSoup
from bs4.element import Tag

CSRF_KEYWORDS = ("csrf", "xsrf", "_token", "authenticity_token", "csrfmiddlewaretoken", "__requestverificationtoken")

class Target:
    def __init__(
        self,
        url: str,
        method: str,
        injectable_params=None,
        fixed_params=None,
        source_url: str = "",
        form_html: str | None = None,
        kind: str = "form",  # form | query
        enctype: str | None = None,
        csrf_param_names=None,
        param_types=None,
        submit_options=None,
    ):
        self.url = url
        self.method = method

        self.injectable_params = tuple(injectable_params) if injectable_params else ()
        self.fixed_params = tuple(fixed_params) if fixed_params else ()

        self.source_url = source_url
        self.form_html = form_html
        self.kind = kind
        self.enctype = enctype

        self.csrf_param_names = tuple(csrf_param_names) if csrf_param_names else ()
        self.param_types = tuple(param_types) if param_types else ()
        self.submit_options = tuple(submit_options) if submit_options else ()

def __repr__(self):
    return (
        f"Target(method={self.method!r}, url={self.url!r}, "
        f"injectable_params={self.injectable_params!r}, fixed_params={self.fixed_params!r}, "
        f"source_url={self.source_url!r})"
    )


def _looks_like_csrf(name: str):
    name_l = name.lower()
    return any(keyword in name_l for keyword in CSRF_KEYWORDS)


#    Если URL содержит query-параметры (?a=b&c=d), возвращаем Target для GET.
def extract_query_target(url: str, source_url: str) -> Target:
    parsed = urlparse(url)
    if not parsed.query:
        return None

    params = parse_qsl(parsed.query, keep_blank_values=True)
    if not params:
        return None

    endpoint = parsed._replace(query="").geturl()

    #injectable - параметры, использующиеся для подставления payload

    injectable = set()
    for key, value in params:
        key = key.strip()
        if key:
            injectable.add(key)
    injectable = tuple(sorted(injectable))

    #базовые значения P: [("id","5"), ("sort","price")]
    fixed = []
    for key, value in params:
        key = key.strip()
        if key:
            fixed.append((key, value))

    return Target(
        url=endpoint,
        method="GET",
        injectable_params=injectable,
        fixed_params=tuple(fixed),
        source_url = source_url,
        kind="query",
        param_types=tuple((name, "query") for name in injectable),
    )

#если атрибут формы Input disabled, то элемент не отправляется
def _is_disabled(control):
    if control.has_attr("disabled"):
        return True

    for fs in control.find_parents("fieldset"):
        if not fs.has_attr("disabled"):
            continue

        legends = fs.find_all("legend", recursive=False)
        if legends and legends[0] in control.parents:
            continue
        return True

    return False


def _option_value(option):
    val = option.get("value")
    if val is None:
        val = option.get_text(strip=True)
    return val or ""

def extract_forms(page_url: str, html: str, include_submit: bool = False):
    soup = BeautifulSoup(html, "html.parser")
    targets = []

    for form in soup.find_all("form"):
        method = (form.get("method") or "GET").upper()

        action = form.get("action") or page_url
        action_url = urljoin(page_url, action)
        enctype = (form.get("enctype") or "application/x-www-form-urlencoded").strip().lower()

        injectable = set()
        fixed: list[tuple[str, str]] = []
        csrf_names = set()
        param_types = {} #name -> тип поля( text, hidden, select, textarea)
        submit_candidates = []


        # 1)проходим по всем формам ввода
        for control in form.find_all(["input", "textarea", "select", "button"]):

            if _is_disabled(control):
                continue

            tag = control.name
            name = (control.get("name") or "").strip()
            if not name:
                continue

            if _looks_like_csrf(name):
                csrf_names.add(name)

            if tag == "input":
                itype = (control.get("type") or "text").lower()
                value = control.get("value") #может быть None
                param_types.setdefault(name, itype)

                if itype == "hidden":
                    fixed.append((name, value or ""))

                elif itype in ("submit", "button"):
                    submit_candidates.append((name, value or ""))

                elif itype == "radio":
                    injectable.add(name)
                    if control.has_attr("checked"):
                        fixed.append((name, value if value is not None else "on"))

                elif itype == "checkbox":
                    injectable.add(name)
                    if control.has_attr("checked"):
                        fixed.append((name, value if value is not None else "on"))
                elif itype in ("reset", "file"):
                    continue
                #закрываем основную массу itype, по типу text, passwd, email, tel...
                else:
                    injectable.add(name)

            elif tag == "textarea":
                param_types.setdefault(name, "textarea")
                injectable.add(name)
                fixed.append((name, control.text or ""))

            elif tag == "select":
                param_types.setdefault(name, "select")
                injectable.add(name)
                options = control.find_all("option")
                if not options:
                    continue
                selected = []
                for option in options:
                    if option.has_attr("selected"):
                        selected.append(option)
                is_multiple = control.has_attr("multiple")
                if is_multiple:
                    for option in selected:
                        fixed.append((name, _option_value(option)))
                else:
                    chosen = selected[0] if selected else options[0]
                    fixed.append((name, _option_value(chosen)))

            elif tag == "button":
                button_type = (control.get("type") or "submit").lower()
                param_types.setdefault(name, f"button:{button_type}")
                if button_type in ("submit", "button"):
                    submit_candidates.append((name, control.get("value") or ""))

            #if include_submit and submit_candidates:
                #fixed.append(submit_candidates[0])

        targets.append(
            Target(
                url = action_url,
                method = method,
                injectable_params = tuple(sorted(injectable))
            )
        )

#исключаем из < href> переход на ненужные ссылки
def is_good_link(href: str):
    if not href:
        return False
    if href.startswith("#"):
        return False
    if href.startswith("mailto:"):
        return False
    if href.startswith("tel:"):
        return False
    if href.startswith("javascript:"):
        return False
    return True

def extract_page_targets(page_url: str, html: str, include_submit: bool = False) -> list[Target]:
    targets = extract_forms(page_url=page_url, html=html, include_submit=include_submit)

    query_target = extract_query_target(page_url, source_url=page_url)
    if query_target:
        targets.append(query_target)
    return targets


def crawl_links(base_url: str, max_pages: int = 20):
    """
      Обходит сайт начиная с base_url и собирает ссылки в пределах того же хоста.
      Возвращает список посещённых URL.
      """
    session = requests.Session()
    queue = deque([base_url]) #очередь ссылок на обход
    visited = set()#посещенные адреса
    all_targets = list[Target] = [] #см параметры класса
    seen_target_keys: set[tuple] = set()
    base_host = urlparse(base_url).netloc #возвращает из https://example.com/path → example.com

    while queue and len(visited) < max_pages:
        url = queue.popleft()
        if url in visited:
            continue
        visited.add(url)


        try:
            resp = session.get(url, timeout=10)
        except requests.RequestException:
            continue

        # проверка на html
        content_type = resp.headers.get("Content-Type", "").lower()
        if "text/html" not in content_type:
            continue

        #работа с html с помощью beautifulsoup
        html = resp.text

        #передает параметры
        page_targets = extract_page_targets(url, html, include_submit=include_submit)










        soup = BeautifulSoup(html, "html.parser")

        for a in soup.find_all("a"):
            href = a.get("href")
            if not is_good_link(href):
                continue

            #делаем url абсолютным: "/about" -> "http://site/about"
            abs_url = urljoin(url, href)

            #остается внутри //site
            abs_url, _frag = urldefrag(abs_url)
            if urlparse(abs_url).netloc != base_host:
                continue
            if abs_url in visited:
                continue

            queue.append(abs_url)


    return list(visited)