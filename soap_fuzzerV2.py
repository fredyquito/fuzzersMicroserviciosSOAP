#!/usr/bin/env python3
"""
soap_fuzzer.py
--------------
Herramienta de fuzzing para microservicios SOAP (o cualquier endpoint HTTP).

Funciones:
  1. Parsea un comando `curl` y reconstruye la petición (URL, método, cabeceras, body).
  2. Fuzzing de métodos HTTP (GET/POST/PUT/DELETE/PATCH/OPTIONS/HEAD/TRACE/...).
  3. Pruebas de path traversal sobre la URL.

El análisis de resultados se basa EXCLUSIVAMENTE en cabeceras de respuesta y
códigos de estado. El body de la petición se envía tal cual viene en el curl y
el body de la respuesta NO se modifica ni se evalúa para decidir hallazgos
(solo se mide su tamaño vía Content-Length / longitud bruta como señal auxiliar).

Objetivo: detectar malas prácticas de programación / configuración, por ejemplo:
  - Métodos peligrosos habilitados (PUT, DELETE, TRACE, CONNECT).
  - Falta de 'Allow' coherente en respuestas 405.
  - Cabeceras de seguridad ausentes.
  - Divulgación de tecnología (Server, X-Powered-By, X-AspNet-Version...).
  - Path traversal reflejado en el comportamiento del servidor (status/headers).

Uso típico:
  python3 soap_fuzzer.py --curl 'curl -X POST https://host/ws -H "SOAPAction: x" -d @body.xml'
  python3 soap_fuzzer.py --curl-file peticion.txt
  cat peticion.txt | python3 soap_fuzzer.py --stdin

Dependencias: requests  (pip install requests)

AVISO: úsalo únicamente contra sistemas para los que tengas autorización explícita.
"""

import argparse
import concurrent.futures
import json
import re
import shlex
import sys
import threading
import time
import urllib.parse
from dataclasses import dataclass, field
from typing import Callable, Dict, List, Optional, Tuple

try:
    import requests
    from requests.structures import CaseInsensitiveDict
except ImportError:
    sys.exit("[!] Falta 'requests'. Instala con: pip install requests")

# Silenciar warnings de TLS cuando se usa --insecure
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


# --------------------------------------------------------------------------- #
#  Colores (desactivables)
# --------------------------------------------------------------------------- #
class C:
    enabled = sys.stdout.isatty()

    @classmethod
    def _w(cls, code, s):
        return f"\033[{code}m{s}\033[0m" if cls.enabled else s

    @classmethod
    def red(cls, s):    return cls._w("91", s)
    @classmethod
    def green(cls, s):  return cls._w("92", s)
    @classmethod
    def yellow(cls, s): return cls._w("93", s)
    @classmethod
    def blue(cls, s):   return cls._w("94", s)
    @classmethod
    def cyan(cls, s):   return cls._w("96", s)
    @classmethod
    def gray(cls, s):   return cls._w("90", s)
    @classmethod
    def bold(cls, s):   return cls._w("1", s)


# --------------------------------------------------------------------------- #
#  Modelo de la petición
# --------------------------------------------------------------------------- #
@dataclass
class ParsedRequest:
    url: str
    method: str = "GET"
    headers: Dict[str, str] = field(default_factory=dict)
    body: Optional[bytes] = None
    verify_tls: bool = True

    def summary(self) -> str:
        lines = [
            f"  URL     : {self.url}",
            f"  Método  : {self.method}",
            f"  Headers : {len(self.headers)}",
        ]
        for k, v in self.headers.items():
            lines.append(f"            {k}: {v}")
        if self.body:
            lines.append(f"  Body    : {len(self.body)} bytes")
        lines.append(f"  TLS     : {'verificar' if self.verify_tls else 'ignorar (insecure)'}")
        return "\n".join(lines)


# --------------------------------------------------------------------------- #
#  Parser de curl
# --------------------------------------------------------------------------- #
def parse_curl(curl_cmd: str) -> ParsedRequest:
    """Convierte una línea de comando `curl` en un ParsedRequest."""
    # Normalizar continuaciones de línea y la palabra inicial 'curl'
    curl_cmd = curl_cmd.replace("\\\n", " ").strip()
    try:
        tokens = shlex.split(curl_cmd)
    except ValueError as e:
        sys.exit(f"[!] No se pudo tokenizar el curl: {e}")

    if tokens and tokens[0] == "curl":
        tokens = tokens[1:]

    url: Optional[str] = None
    method: Optional[str] = None
    headers: Dict[str, str] = {}
    data_parts: List[str] = []
    verify_tls = True
    cookie: Optional[str] = None
    user: Optional[str] = None

    i = 0
    n = len(tokens)
    while i < n:
        t = tokens[i]

        if t in ("-X", "--request"):
            method = tokens[i + 1].upper(); i += 2; continue

        if t in ("-H", "--header"):
            raw = tokens[i + 1]
            if ":" in raw:
                k, v = raw.split(":", 1)
                headers[k.strip()] = v.strip()
            i += 2; continue

        if t in ("-b", "--cookie"):
            cookie = tokens[i + 1]; i += 2; continue

        if t in ("-u", "--user"):
            user = tokens[i + 1]; i += 2; continue

        if t in ("-A", "--user-agent"):
            headers["User-Agent"] = tokens[i + 1]; i += 2; continue

        if t in ("-e", "--referer"):
            headers["Referer"] = tokens[i + 1]; i += 2; continue

        if t in ("-d", "--data", "--data-raw", "--data-binary", "--data-ascii"):
            val = tokens[i + 1]
            if val.startswith("@"):
                path = val[1:]
                try:
                    with open(path, "rb") as f:
                        data_parts.append(f.read().decode("utf-8", "replace"))
                except OSError as e:
                    sys.exit(f"[!] No se pudo leer el archivo de datos '{path}': {e}")
            else:
                data_parts.append(val)
            i += 2; continue

        if t in ("-k", "--insecure"):
            verify_tls = False; i += 1; continue

        # Flags que ignoramos pero consumen (o no) un argumento
        if t in ("--compressed", "-s", "--silent", "-i", "--include",
                 "-L", "--location", "-v", "--verbose", "-f", "--fail",
                 "-g", "--globoff"):
            i += 1; continue
        if t in ("-o", "--output", "-w", "--write-out", "--connect-timeout",
                 "--max-time", "-m", "--resolve", "--cacert", "-x", "--proxy"):
            i += 2; continue

        # Cualquier token que parezca URL
        if t.startswith("http://") or t.startswith("https://"):
            url = t; i += 1; continue

        # Token suelto no reconocido: si aún no hay URL y parece host, úsalo
        if url is None and not t.startswith("-"):
            url = t
        i += 1

    if cookie:
        headers.setdefault("Cookie", cookie)
    if user:
        import base64
        token = base64.b64encode(user.encode()).decode()
        headers.setdefault("Authorization", f"Basic {token}")

    if url is None:
        sys.exit("[!] No se encontró URL en el comando curl.")

    # Si hay datos pero no método explícito, curl usa POST
    if method is None:
        method = "POST" if data_parts else "GET"

    body = ("&".join(data_parts)).encode("utf-8") if data_parts else None

    return ParsedRequest(
        url=url, method=method, headers=headers,
        body=body, verify_tls=verify_tls
    )


# --------------------------------------------------------------------------- #
#  Parser de colecciones Postman (v2.0 / v2.1)
# --------------------------------------------------------------------------- #
def _resolve_vars(text: Optional[str], variables: Dict[str, str]) -> Optional[str]:
    """Reemplaza {{clave}} por su valor si existe en 'variables'."""
    if not text:
        return text
    return re.sub(r"\{\{([^}]+)\}\}",
                  lambda m: str(variables.get(m.group(1).strip(), m.group(0))),
                  text)


def _postman_request(r, variables: Dict[str, str], verify_tls: bool) -> Optional[ParsedRequest]:
    """Convierte un objeto 'request' de Postman en ParsedRequest."""
    if isinstance(r, str):                       # forma abreviada: solo URL (GET)
        r = {"method": "GET", "url": r}

    method = (r.get("method") or "GET").upper()

    # ---- URL ----
    url = r.get("url")
    if isinstance(url, dict):
        raw = url.get("raw")
        if raw:
            url = raw
        else:
            host = url.get("host", "")
            host = ".".join(host) if isinstance(host, list) else host
            path = url.get("path", "")
            path = "/".join(path) if isinstance(path, list) else path
            proto = url.get("protocol", "https")
            url = f"{proto}://{host}/{path}"
    url = _resolve_vars(url, variables)

    # ---- Headers (se omiten los deshabilitados) ----
    headers: Dict[str, str] = {}
    for h in r.get("header", []) or []:
        if isinstance(h, dict) and not h.get("disabled"):
            k = h.get("key")
            if k:
                headers[_resolve_vars(k, variables)] = _resolve_vars(h.get("value", ""), variables)

    # ---- Body ----
    body = None
    b = r.get("body") or {}
    mode = b.get("mode")
    if mode == "raw":
        body = (_resolve_vars(b.get("raw", ""), variables) or "").encode("utf-8")
    elif mode == "urlencoded":
        pairs = [f"{p.get('key','')}={p.get('value','')}"
                 for p in b.get("urlencoded", []) if not p.get("disabled")]
        body = (_resolve_vars("&".join(pairs), variables) or "").encode("utf-8")
        headers.setdefault("Content-Type", "application/x-www-form-urlencoded")
    elif mode == "formdata":
        pairs = [f"{p.get('key','')}={p.get('value','')}"
                 for p in b.get("formdata", []) if not p.get("disabled")]
        body = (_resolve_vars("&".join(pairs), variables) or "").encode("utf-8")

    if not url:
        return None
    return ParsedRequest(url=url, method=method, headers=headers,
                         body=body, verify_tls=verify_tls)


def parse_postman(path: str, variables: Optional[Dict[str, str]] = None,
                  verify_tls: bool = True) -> List[Tuple[str, ParsedRequest]]:
    """Lee una colección Postman y devuelve [(nombre, ParsedRequest), ...]."""
    variables = dict(variables or {})
    try:
        with open(path, encoding="utf-8") as f:
            data = json.load(f)
    except (OSError, json.JSONDecodeError) as e:
        sys.exit(f"[!] No se pudo leer la colección Postman '{path}': {e}")

    # Variables definidas en la colección (no pisan las pasadas por el usuario)
    for v in data.get("variable", []) or []:
        k = v.get("key")
        if k and k not in variables:
            variables[k] = v.get("value", "")

    out: List[Tuple[str, ParsedRequest]] = []

    def walk(items, prefix=""):
        for it in items or []:
            name = it.get("name", "sin-nombre")
            full = f"{prefix}{name}"
            if "item" in it:                      # carpeta: recursión
                walk(it["item"], prefix=f"{full} / ")
            elif "request" in it:
                pr = _postman_request(it["request"], variables, verify_tls)
                if pr:
                    out.append((full, pr))

    walk(data.get("item", []))
    if not out:
        sys.exit("[!] La colección no contenía peticiones utilizables.")
    return out


def _unresolved_vars(req: ParsedRequest) -> List[str]:
    """Lista de variables {{...}} sin resolver en url/headers/body."""
    blob = req.url + " " + " ".join(f"{k}:{v}" for k, v in req.headers.items())
    if req.body:
        blob += " " + req.body.decode("utf-8", "replace")
    return sorted(set(re.findall(r"\{\{([^}]+)\}\}", blob)))


def _apply_vars(req: ParsedRequest, variables: Dict[str, str]) -> None:
    """Sustituye variables en una ParsedRequest ya construida (in-place)."""
    req.url = _resolve_vars(req.url, variables)
    req.headers = {_resolve_vars(k, variables): _resolve_vars(v, variables)
                   for k, v in req.headers.items()}
    if req.body:
        req.body = (_resolve_vars(req.body.decode("utf-8", "replace"), variables) or "").encode("utf-8")


# --------------------------------------------------------------------------- #
#  Menú interactivo
# --------------------------------------------------------------------------- #
def _prompt(msg: str, default: str = "") -> str:
    try:
        val = input(msg).strip()
    except EOFError:
        return default
    return val or default


def interactive_menu() -> Tuple[List[Tuple[str, ParsedRequest]], Optional[str]]:
    """Menú para elegir la fuente de entrada. Devuelve (targets, proxy)."""
    print(C.bold("\n==============================="))
    print(C.bold("   SOAP / HTTP Fuzzer - Menú"))
    print(C.bold("===============================\n"))
    print("  Fuente de entrada:")
    print("    1) curl directo")
    print("    2) colección de Postman (.json)")
    choice = _prompt("\n  Opción [1/2]: ", "1")

    targets: List[Tuple[str, ParsedRequest]] = []

    if choice == "2":
        path = _prompt("  Ruta de la colección .json: ")
        if not path:
            sys.exit("[!] No se indicó ruta.")
        all_reqs = parse_postman(path)
        print(C.bold(f"\n  {len(all_reqs)} peticiones encontradas:"))
        for idx, (name, pr) in enumerate(all_reqs, 1):
            print(f"    {idx:>3}) {C.cyan(pr.method):<6} {name}")
        sel = _prompt("\n  Selecciona (ej: 1,3,5  |  1-4  |  all): ", "all").lower()
        targets = _select_targets(all_reqs, sel)
    else:
        print("\n  Pega el comando curl (termina con una línea vacía):")
        lines: List[str] = []
        while True:
            try:
                ln = input()
            except EOFError:
                break
            if ln.strip() == "":
                break
            lines.append(ln)
        curl_cmd = "\n".join(lines)
        if not curl_cmd.strip():
            sys.exit("[!] No se ingresó ningún curl.")
        targets = [("curl", parse_curl(curl_cmd))]

    # Proxy
    use_burp = _prompt("\n  ¿Enrutar por Burp (127.0.0.1:8080)? [S/n]: ", "s").lower()
    proxy = None
    if use_burp in ("s", "si", "sí", "y", "yes", ""):
        proxy = "http://127.0.0.1:8080"
        for _, pr in targets:
            pr.verify_tls = False
    else:
        custom = _prompt("  Proxy personalizado (vacío = sin proxy): ")
        proxy = custom or None

    return targets, proxy


def _select_targets(all_reqs: List[Tuple[str, ParsedRequest]],
                    sel: str) -> List[Tuple[str, ParsedRequest]]:
    """Interpreta una selección tipo '1,3', '2-5' o 'all'."""
    if sel in ("all", "*", "todos"):
        return all_reqs
    chosen: List[int] = []
    for part in sel.replace(" ", "").split(","):
        if "-" in part:
            try:
                a, b = part.split("-", 1)
                chosen.extend(range(int(a), int(b) + 1))
            except ValueError:
                continue
        elif part.isdigit():
            chosen.append(int(part))
    picked = [all_reqs[i - 1] for i in chosen if 1 <= i <= len(all_reqs)]
    if not picked:
        sys.exit("[!] Selección vacía o inválida.")
    return picked


# --------------------------------------------------------------------------- #
#  Envío de peticiones
# --------------------------------------------------------------------------- #
@dataclass
class Result:
    label: str
    method: str
    url: str
    status: Optional[int]
    reason: str
    resp_headers: CaseInsensitiveDict
    length: int
    elapsed_ms: int
    error: Optional[str] = None


def send(session: requests.Session, method: str, url: str,
         headers: Dict[str, str], body: Optional[bytes],
         verify: bool, timeout: float, label: str) -> Result:
    start = time.perf_counter()
    try:
        r = session.request(
            method=method, url=url, headers=headers, data=body,
            verify=verify, timeout=timeout, allow_redirects=False,
        )
        elapsed = int((time.perf_counter() - start) * 1000)
        # Longitud: preferimos Content-Length declarado; si no, bytes recibidos.
        cl = r.headers.get("Content-Length")
        length = int(cl) if (cl and cl.isdigit()) else len(r.content)
        return Result(label, method, url, r.status_code, r.reason,
                      r.headers, length, elapsed)
    except requests.RequestException as e:
        elapsed = int((time.perf_counter() - start) * 1000)
        return Result(label, method, url, None, "", CaseInsensitiveDict(),
                      0, elapsed, error=str(e))


# --------------------------------------------------------------------------- #
#  Ejecución concurrente (hilos + intervalo entre lotes)
# --------------------------------------------------------------------------- #
_thread_local = threading.local()


def get_session(proxy: Optional[str]) -> requests.Session:
    """Una sesión requests por hilo (Session no es totalmente thread-safe)."""
    s = getattr(_thread_local, "session", None)
    if s is None:
        s = requests.Session()
        if proxy:
            s.proxies = {"http": proxy, "https": proxy}
        _thread_local.session = s
    return s


def execute_concurrent(tasks: list, worker: Callable, threads: int,
                       interval_s: float) -> list:
    """
    Ejecuta 'worker(task)' sobre cada elemento de 'tasks'.
    Lanza en lotes de 'threads' hilos concurrentes y espera 'interval_s'
    segundos entre el fin de un lote y el inicio del siguiente.
    Devuelve los resultados en el MISMO orden que 'tasks'.
    """
    results: list = [None] * len(tasks)
    threads = max(1, threads)
    with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as ex:
        start = 0
        while start < len(tasks):
            batch = range(start, min(start + threads, len(tasks)))
            futs = {ex.submit(worker, tasks[idx]): idx for idx in batch}
            for fut in concurrent.futures.as_completed(futs):
                results[futs[fut]] = fut.result()
            start += threads
            if interval_s and start < len(tasks):
                time.sleep(interval_s)
    return results


# --------------------------------------------------------------------------- #
#  Análisis basado en cabeceras / status
# --------------------------------------------------------------------------- #
DANGEROUS_METHODS = {"PUT", "DELETE", "PATCH", "TRACE", "CONNECT", "MOVE", "COPY"}

SECURITY_HEADERS = [
    "Strict-Transport-Security",
    "Content-Security-Policy",
    "X-Content-Type-Options",
    "X-Frame-Options",
    "Referrer-Policy",
    "Permissions-Policy",
]

DISCLOSURE_HEADERS = [
    "Server",
    "X-Powered-By",
    "X-AspNet-Version",
    "X-AspNetMvc-Version",
    "X-Generator",
    "X-Runtime",
    "Via",
]


def classify_method(res: Result) -> Tuple[str, List[str]]:
    """Devuelve (nivel, notas) para un resultado de fuzzing de métodos."""
    notes: List[str] = []
    level = "info"

    if res.error:
        return "error", [res.error]

    code = res.status or 0
    accepted = code < 400 or code in (401, 403)

    if res.method in DANGEROUS_METHODS and code < 400:
        level = "high"
        notes.append(f"Método peligroso {res.method} aceptado (status {code}).")

    if res.method == "TRACE" and code == 200:
        level = "high"
        notes.append("TRACE habilitado: posible Cross-Site Tracing (XST).")

    if res.method == "OPTIONS" and code < 400:
        allow = res.resp_headers.get("Allow") or res.resp_headers.get("Access-Control-Allow-Methods")
        if allow:
            notes.append(f"OPTIONS anuncia métodos: {allow}")
            dangerous_adv = DANGEROUS_METHODS & {m.strip().upper() for m in allow.split(",")}
            if dangerous_adv:
                level = "medium" if level == "info" else level
                notes.append(f"Métodos peligrosos anunciados en Allow: {', '.join(sorted(dangerous_adv))}")

    if code == 405:
        allow = res.resp_headers.get("Allow")
        if not allow:
            level = "low" if level == "info" else level
            notes.append("405 sin cabecera 'Allow' (mala práctica: no indica métodos válidos).")

    if not accepted and level == "info":
        notes.append(f"Rechazado (status {code}).")

    return level, notes


def header_hygiene(res: Result) -> List[Tuple[str, str]]:
    """Revisa cabeceras de seguridad y de divulgación sobre una respuesta base."""
    findings: List[Tuple[str, str]] = []
    h = res.resp_headers

    for sh in SECURITY_HEADERS:
        if sh not in h:
            findings.append(("low", f"Falta cabecera de seguridad: {sh}"))

    for dh in DISCLOSURE_HEADERS:
        if dh in h:
            findings.append(("medium", f"Divulgación de tecnología en '{dh}': {h[dh]}"))

    # CORS permisivo
    acao = h.get("Access-Control-Allow-Methods") or h.get("Access-Control-Allow-Origin")
    if h.get("Access-Control-Allow-Origin") == "*":
        findings.append(("medium", "CORS abierto: Access-Control-Allow-Origin: *"))
    if h.get("Access-Control-Allow-Credentials", "").lower() == "true" and \
       h.get("Access-Control-Allow-Origin") == "*":
        findings.append(("high", "CORS inseguro: credenciales permitidas con origen '*'."))

    return findings


# --------------------------------------------------------------------------- #
#  Payloads de path traversal
# --------------------------------------------------------------------------- #
# Lista por defecto, usada si no se indica --traversal-file.
DEFAULT_TRAVERSAL_PAYLOADS = [
    "../../../../etc/passwd",
    "..%2f..%2f..%2f..%2fetc%2fpasswd",
    "..%252f..%252f..%252fetc%252fpasswd",
    "....//....//....//etc/passwd",
    "..\\..\\..\\..\\windows\\win.ini",
    "..%5c..%5c..%5cwindows%5cwin.ini",
    "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
    "/etc/passwd",
    "../" * 8 + "etc/passwd",
]

# Lista por defecto de métodos, usada si no se indica --methods-file ni --methods.
DEFAULT_METHODS = ["GET", "POST", "PUT", "DELETE", "PATCH",
                   "OPTIONS", "HEAD", "TRACE", "CONNECT"]


def load_lines(path: str, upper: bool = False) -> List[str]:
    """
    Lee un .txt y devuelve una entrada por línea.
    Ignora líneas vacías y comentarios que empiezan por '#'.
    """
    try:
        with open(path, "r", encoding="utf-8") as f:
            raw = f.readlines()
    except OSError as e:
        sys.exit(f"[!] No se pudo leer el archivo '{path}': {e}")

    out: List[str] = []
    for ln in raw:
        s = ln.strip()
        if not s or s.startswith("#"):
            continue
        out.append(s.upper() if upper else s)
    if not out:
        sys.exit(f"[!] El archivo '{path}' no contenía entradas utilizables.")
    return out


def build_traversal_urls(base_url: str,
                         payloads: List[str]) -> List[Tuple[str, str]]:
    """
    Devuelve lista de (payload, url) inyectando traversal al final del path.
    Mantiene el query string original.
    """
    parsed = urllib.parse.urlsplit(base_url)
    path = parsed.path if parsed.path else "/"
    if not path.endswith("/"):
        path = path.rsplit("/", 1)[0] + "/"

    urls = []
    for p in payloads:
        new_path = path + p
        new = urllib.parse.urlunsplit(
            (parsed.scheme, parsed.netloc, new_path, parsed.query, "")
        )
        urls.append((p, new))
    return urls


def classify_traversal(baseline: Result, res: Result) -> Tuple[str, List[str]]:
    """
    Compara una respuesta de traversal contra la baseline usando SOLO
    status + cabeceras (Content-Type, Content-Length).
    """
    notes: List[str] = []
    if res.error:
        return "error", [res.error]

    code = res.status or 0
    level = "info"

    # Señal 1: cambio de código respecto a baseline hacia un 2xx
    if baseline.status and baseline.status >= 400 and code < 400:
        level = "high"
        notes.append(f"Status cambió {baseline.status} -> {code} con payload traversal.")

    # Señal 2: cambio notable de Content-Length (posible archivo distinto servido)
    if code < 400 and baseline.length and res.length:
        ratio = res.length / max(baseline.length, 1)
        if ratio > 1.5 or ratio < 0.5:
            level = "medium" if level == "info" else level
            notes.append(
                f"Content-Length difiere de baseline "
                f"({baseline.length} -> {res.length})."
            )

    # Señal 3: Content-Type sospechoso (text/plain donde la base era xml/json)
    ct_base = (baseline.resp_headers.get("Content-Type") or "").split(";")[0].strip()
    ct_now = (res.resp_headers.get("Content-Type") or "").split(";")[0].strip()
    if ct_base and ct_now and ct_base != ct_now:
        level = "medium" if level == "info" else level
        notes.append(f"Content-Type cambió: {ct_base} -> {ct_now}")

    # Señal 4: cabeceras típicas de descarga de archivo
    cd = res.resp_headers.get("Content-Disposition")
    if cd and code < 400:
        level = "high"
        notes.append(f"Content-Disposition presente: {cd}")

    if level == "info":
        notes.append(f"Sin anomalía evidente (status {code}).")
    return level, notes


# --------------------------------------------------------------------------- #
#  Impresión de hallazgos
# --------------------------------------------------------------------------- #
LEVEL_FMT = {
    "high":   lambda s: C.red(C.bold(s)),
    "medium": lambda s: C.yellow(s),
    "low":    lambda s: C.cyan(s),
    "info":   lambda s: C.gray(s),
    "error":  lambda s: C.gray(s),
}
LEVEL_TAG = {
    "high": "ALTO", "medium": "MEDIO", "low": "BAJO",
    "info": "info", "error": "err ",
}


def tag(level: str) -> str:
    return LEVEL_FMT.get(level, str)(f"[{LEVEL_TAG.get(level, level)}]")


# --------------------------------------------------------------------------- #
#  Flujo principal
# --------------------------------------------------------------------------- #
def run(req: ParsedRequest, methods: List[str], timeout: float,
        delay: float, do_methods: bool, do_traversal: bool,
        proxy: Optional[str] = None,
        traversal_payloads: Optional[List[str]] = None,
        threads: int = 1, interval_s: float = 0.0) -> None:

    if proxy:
        print(C.gray(f"[*] Tráfico enrutado por proxy: {proxy}"))
    if threads > 1 or interval_s:
        print(C.gray(f"[*] Concurrencia: {threads} hilo(s) por lote, "
                     f"{int(interval_s * 1000)} ms entre lotes"))
    summary_counts = {"high": 0, "medium": 0, "low": 0}

    def bump(level: str):
        if level in summary_counts:
            summary_counts[level] += 1

    print(C.bold("\n=== Petición parseada ==="))
    print(req.summary())

    # Baseline con el método original (secuencial: sirve de referencia para todo)
    baseline = send(get_session(proxy), req.method, req.url, req.headers,
                    req.body, req.verify_tls, timeout, "baseline")

    # ---- Higiene de cabeceras sobre la respuesta base ----
    if baseline.error:
        print(C.red(f"\n[!] La petición base falló: {baseline.error}"))
    else:
        print(C.bold("\n=== Higiene de cabeceras (respuesta base) ==="))
        print(f"  Base: {req.method} -> {baseline.status} {baseline.reason} "
              f"({baseline.length} bytes, {baseline.elapsed_ms} ms)")
        hyg = header_hygiene(baseline)
        if not hyg:
            print(C.green("  Sin observaciones de cabeceras."))
        for level, msg in hyg:
            bump(level)
            print(f"  {tag(level)} {msg}")

    # ---- Fuzzing de métodos (concurrente) ----
    if do_methods:
        print(C.bold("\n=== Fuzzing de métodos HTTP ==="))
        print(C.gray(f"  {'MÉTODO':8} {'STATUS':6} {'LEN':>8} {'ms':>6}  notas"))

        def method_worker(m):
            return send(get_session(proxy), m, req.url, req.headers, req.body,
                        req.verify_tls, timeout, f"method:{m}")

        results = execute_concurrent(methods, method_worker, threads, interval_s)
        for m, res in zip(methods, results):
            level, notes = classify_method(res)
            status_s = str(res.status) if res.status else "ERR"
            line = f"  {m:8} {status_s:6} {res.length:>8} {res.elapsed_ms:>6}"
            print(line + "  " + (tag(level) if level != "info" else ""))
            for nt in notes:
                if level in ("high", "medium", "low"):
                    bump(level)
                    print(f"           {LEVEL_FMT.get(level, str)('> ' + nt)}")
                else:
                    print(C.gray(f"           > {nt}"))

    # ---- Path traversal (concurrente) ----
    if do_traversal:
        print(C.bold("\n=== Path traversal (análisis por status + cabeceras) ==="))
        if baseline.error:
            print(C.gray("  Omitido: la baseline falló, no hay referencia para comparar."))
        else:
            payloads = traversal_payloads or DEFAULT_TRAVERSAL_PAYLOADS
            trav_urls = build_traversal_urls(req.url, payloads)
            # Se conservan el método y el body originales de la petición,
            # para no alterar la semántica del servicio (p. ej. SOAP con POST).
            trav_method = req.method

            def trav_worker(item):
                _payload, turl = item
                return send(get_session(proxy), trav_method, turl, req.headers,
                            req.body, req.verify_tls, timeout, "traversal")

            results = execute_concurrent(trav_urls, trav_worker, threads, interval_s)
            for (payload, _turl), res in zip(trav_urls, results):
                level, notes = classify_traversal(baseline, res)
                status_s = str(res.status) if res.status else "ERR"
                print(f"  {tag(level)} {status_s:4} payload: {payload}")
                for nt in notes:
                    if level in ("high", "medium", "low"):
                        bump(level)
                    print(C.gray(f"           > {nt}"))

    # ---- Resumen ----
    print(C.bold("\n=== Resumen ==="))
    print(f"  Hallazgos ALTO : {C.red(str(summary_counts['high']))}")
    print(f"  Hallazgos MEDIO: {C.yellow(str(summary_counts['medium']))}")
    print(f"  Hallazgos BAJO : {C.cyan(str(summary_counts['low']))}")
    print()


def read_curl_input(args) -> str:
    if args.curl:
        return args.curl
    if args.curl_file:
        try:
            with open(args.curl_file, "r", encoding="utf-8") as f:
                return f.read()
        except OSError as e:
            sys.exit(f"[!] No se pudo leer '{args.curl_file}': {e}")
    if args.stdin:
        return sys.stdin.read()
    sys.exit("[!] Indica el curl con --curl, --curl-file o --stdin.")


def _build_var_dict(pairs: Optional[List[str]]) -> Dict[str, str]:
    out: Dict[str, str] = {}
    for p in pairs or []:
        if "=" in p:
            k, v = p.split("=", 1)
            out[k.strip()] = v
    return out


def main():
    ap = argparse.ArgumentParser(
        description="Fuzzer de métodos y path traversal para microservicios SOAP/HTTP "
                    "(análisis por cabeceras y status).\n"
                    "Sin argumentos de entrada abre un menú interactivo.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    src = ap.add_argument_group("entrada (si se omite todo, se abre el menú)")
    src.add_argument("--curl", help="Comando curl entre comillas.")
    src.add_argument("--curl-file", help="Archivo con el comando curl.")
    src.add_argument("--stdin", action="store_true", help="Leer el curl desde stdin.")
    src.add_argument("--postman", help="Ruta de una colección Postman (.json).")
    src.add_argument("--select", default="all",
                     help="Qué peticiones de la colección usar: 'all', '1,3,5' o '2-6'.")
    src.add_argument("--var", action="append",
                     help="Variable de colección clave=valor (repetible). Ej: --var baseUrl=https://host")

    ap.add_argument("--methods", default=None,
                    help="Lista de métodos separados por coma. Por defecto: "
                         + ",".join(DEFAULT_METHODS))
    ap.add_argument("--methods-file",
                    help="Archivo .txt con un método por línea (ignora vacías y '#'). "
                         "Tiene prioridad sobre --methods.")
    ap.add_argument("--traversal-file",
                    help="Archivo .txt con un payload de path traversal por línea "
                         "(ignora vacías y '#'). Reemplaza la lista por defecto.")
    ap.add_argument("--timeout", type=float, default=15.0, help="Timeout por petición (s).")
    ap.add_argument("--threads", type=int, default=1,
                    help="Hilos concurrentes por lote (ej: 10). Por defecto 1 (secuencial).")
    ap.add_argument("--interval", type=float, default=0.0,
                    help="Milisegundos de espera entre lotes de hilos (ej: 500).")
    ap.add_argument("--delay", type=float, default=0.0,
                    help="(Compat.) Pausa en segundos entre peticiones cuando --threads=1.")
    ap.add_argument("--no-methods", action="store_true", help="Omitir el fuzzing de métodos.")
    ap.add_argument("--no-traversal", action="store_true", help="Omitir path traversal.")
    ap.add_argument("--no-color", action="store_true", help="Desactivar colores.")

    proxy_grp = ap.add_argument_group("proxy")
    proxy_grp.add_argument("--proxy", help="Proxy HTTP(S), ej: http://127.0.0.1:8080")
    proxy_grp.add_argument("--burp", action="store_true",
                           help="Atajo: usa http://127.0.0.1:8080 y desactiva verificación TLS "
                                "(necesario para HTTPS vía Burp salvo que confíes en su CA).")

    args = ap.parse_args()
    if args.no_color:
        C.enabled = False

    has_input = any([args.curl, args.curl_file, args.stdin, args.postman])
    proxy = args.proxy
    variables = _build_var_dict(args.var)

    # ---- Reunir los objetivos (targets) ----
    targets: List[Tuple[str, ParsedRequest]] = []

    if not has_input:
        # Modo interactivo: menú
        targets, proxy = interactive_menu()
    elif args.postman:
        all_reqs = parse_postman(args.postman, variables=variables)
        targets = _select_targets(all_reqs, args.select)
    else:
        req = parse_curl(read_curl_input(args))
        targets = [("curl", req)]

    # ---- Proxy / TLS ----
    if args.burp:
        proxy = proxy or "http://127.0.0.1:8080"
        for _, pr in targets:
            pr.verify_tls = False

    # Resolver variables aún pendientes y avisos de TLS
    for name, pr in targets:
        if variables:
            _apply_vars(pr, variables)
        pending = _unresolved_vars(pr)
        if pending:
            if sys.stdin.isatty():
                print(C.yellow(f"\n[!] '{name}' tiene variables sin resolver: {', '.join(pending)}"))
                resolved = {}
                for var in pending:
                    val = _prompt(f"    {var} = ")
                    if val:
                        resolved[var] = val
                _apply_vars(pr, resolved)
            else:
                print(C.yellow(f"[!] '{name}' tiene variables sin resolver "
                               f"({', '.join(pending)}). Usa --var clave=valor."))
        if proxy and pr.verify_tls:
            print(C.yellow("[!] Proxy activo con verificación TLS ON: los HTTPS pueden fallar "
                           "si el proxy no tiene CA de confianza. Usa --burp o -k."))

    interactive = (not has_input) and sys.stdin.isatty()

    # ---- Métodos: --methods-file > --methods > prompt (menú) > por defecto ----
    methods_file = args.methods_file
    if not methods_file and interactive and not args.methods:
        methods_file = _prompt(
            "\n  Archivo .txt de métodos (vacío = lista por defecto): ") or None
    if methods_file:
        methods = load_lines(methods_file, upper=True)
    elif args.methods:
        methods = [m.strip().upper() for m in args.methods.split(",") if m.strip()]
    else:
        methods = list(DEFAULT_METHODS)

    # ---- Payloads traversal: --traversal-file > prompt (menú) > por defecto ----
    traversal_file = args.traversal_file
    if not traversal_file and interactive and not args.no_traversal:
        traversal_file = _prompt(
            "  Archivo .txt de payloads traversal (vacío = lista por defecto): ") or None
    traversal_payloads = load_lines(traversal_file) if traversal_file else list(DEFAULT_TRAVERSAL_PAYLOADS)

    # ---- Concurrencia: prompt en el menú o flags CLI ----
    if interactive:
        t_in = _prompt(f"  Hilos concurrentes por lote [{args.threads}]: ", str(args.threads))
        try:
            args.threads = int(t_in)
        except ValueError:
            pass
        i_in = _prompt(f"  Intervalo entre lotes en ms [{int(args.interval)}]: ",
                       str(int(args.interval)))
        try:
            args.interval = float(i_in)
        except ValueError:
            pass

    threads = max(1, args.threads)
    interval_s = args.interval / 1000.0
    # Compatibilidad: con 1 hilo y sin intervalo, --delay sigue espaciando peticiones.
    if threads == 1 and not interval_s and args.delay:
        interval_s = args.delay

    print(C.gray(f"\n[*] Métodos a fuzzear: {len(methods)} | "
                 f"payloads traversal: {len(traversal_payloads)} | "
                 f"hilos: {threads} | intervalo: {int(interval_s * 1000)} ms"))

    # ---- Ejecutar cada objetivo ----
    try:
        total = len(targets)
        for idx, (name, req) in enumerate(targets, 1):
            if total > 1:
                print(C.bold(f"\n\n########## [{idx}/{total}] {name} ##########"))
            run(req, methods, args.timeout, args.delay,
                do_methods=not args.no_methods,
                do_traversal=not args.no_traversal,
                proxy=proxy,
                traversal_payloads=traversal_payloads,
                threads=threads,
                interval_s=interval_s)
    except KeyboardInterrupt:
        print(C.gray("\n[interrumpido]"))


if __name__ == "__main__":
    main()
