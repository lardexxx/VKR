from dataclasses import dataclass, field
import requests

from crawler_my import Target


#настроим по умолчанию конфиг для формирования запроса
@dataclass
class RequestConfig:
    timeout: int = 10               #время ожидания процесса: (подключение/ответ)
    verify_ssl: bool = True
    allow_redirects: bool = True
    max_redirects: int = 10
    retries: int = 1                #кол-во допа попыток при неудаче
    retry_delay_sec: float = 0.35   #пауза между попытками
    retry_on_status: tuple[int,] = (429, 500, 502, 503, 504)
    headers: dict = None

    def __post_init__(self):
        if self.headers is None:
            self.headers = {}

@dataclass
class ExecutionResult:
    success: bool = True
    response: requests.Response = None
    error: str = None
    attempts: int
    method: str
    url: str
    tested_param: str
    payload: str

def create_session(config: RequestConfig | None = None) -> requests.Session:
    if config is not None and not isinstance(config, RequestConfig):
        raise TypeError("config must be RequestConfig or None")
    cfg = config or RequestConfig()
    session = requests.Session()
    session.max_redirects = config.max_redirects
    session.headers.update({"User-Agent": "vkr_scanner"})
    if cfg.headers:
        session.headers.update(cfg.headers)
    return session

def build_request_pairs(
        target: Target,
        tested_param: str,
        payload: str,
        default_injectable_value: str = "",
) -> list[tuple[str, str]]:
    pairs = []
    existing_counts = {}
    for key, value in target.fixed_params:
        if key == tested_param:
            pairs.append((key, payload))
        else:
            pairs.append((key, value))
        existing_counts[key] = existing_counts.get(key, 0) + 1  #увеличение счетчика для ключа в словаре

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

def build_request_kwargs(target, pairs) -> dict:
    method = target.method
    if method == "GET":
        return {"params": pairs}

    enctype = (targer.enctype or "application/x-www-form-urlencoded")