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
import csv
import datetime
import json
import os
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
    ts: str = ""           # fecha/hora de inicio de la petición (ISO)
    payload: str = ""      # payload evaluado (si aplica)
    body_text: str = ""    # body de respuesta (solo si keep_body=True, p. ej. PoC cmdi)


def send(session: requests.Session, method: str, url: str,
         headers: Dict[str, str], body: Optional[bytes],
         verify: bool, timeout: float, label: str,
         payload: str = "", keep_body: bool = False) -> Result:
    ts = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]
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
        # El body solo se retiene para la fase de confirmación de RCE (cmdi).
        btext = r.text[:20000] if keep_body else ""
        return Result(label, method, url, r.status_code, r.reason,
                      r.headers, length, elapsed, ts=ts, payload=payload,
                      body_text=btext)
    except requests.RequestException as e:
        elapsed = int((time.perf_counter() - start) * 1000)
        return Result(label, method, url, None, "", CaseInsensitiveDict(),
                      0, elapsed, error=str(e), ts=ts, payload=payload)


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
                       interval_s: float,
                       on_done: Optional[Callable] = None,
                       key_fn: Optional[Callable] = None) -> list:
    """
    Ejecuta 'worker(task)' sobre cada elemento de 'tasks'.
    Lanza en lotes de 'threads' hilos concurrentes y espera 'interval_s'
    segundos entre el fin de un lote y el inicio del siguiente.
    Devuelve los resultados en el MISMO orden que 'tasks'.

    - 'on_done(n_hechas, total)' se llama al completar cada tarea (barra de progreso).
    - 'key_fn(task)' identifica una tarea: si dos tareas comparten clave, la
      repetida NO se vuelve a ejecutar (se reutiliza el resultado del antecesor).
      Así ningún hilo repite una ejecución ya realizada.
    """
    n = len(tasks)
    results: list = [None] * n
    threads = max(1, threads)
    total_to_run = n
    done = 0
    done_lock = threading.Lock()

    # Dedupe: mapear clave -> primer índice que la ejecuta.
    seen: Dict = {}
    dup_of: Dict[int, int] = {}      # índice duplicado -> índice que sí se ejecuta
    unique_idx: List[int] = []
    for idx, task in enumerate(tasks):
        if key_fn is not None:
            k = key_fn(task)
            if k in seen:
                dup_of[idx] = seen[k]
                continue
            seen[k] = idx
        unique_idx.append(idx)
    total_to_run = len(unique_idx)

    def _progress():
        nonlocal done
        with done_lock:
            done += 1
            if on_done:
                on_done(done, total_to_run)

    with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as ex:
        pos = 0
        while pos < len(unique_idx):
            batch = unique_idx[pos:pos + threads]
            futs = {}
            for idx in batch:
                fut = ex.submit(worker, tasks[idx])
                futs[fut] = idx
            for fut in concurrent.futures.as_completed(futs):
                results[futs[fut]] = fut.result()
                _progress()
            pos += threads
            if interval_s and pos < len(unique_idx):
                time.sleep(interval_s)

    # Rellenar los duplicados con el resultado del antecesor ya ejecutado.
    for dup, src in dup_of.items():
        results[dup] = results[src]
    return results


# --------------------------------------------------------------------------- #
#  Barra de progreso (hilo-segura, escribe a stderr)
# --------------------------------------------------------------------------- #
class Progress:
    def __init__(self, enabled: bool = True, width: int = 32):
        self.enabled = enabled and sys.stderr.isatty()
        self.width = width

    def update(self, done: int, total: int, prefix: str = ""):
        if not self.enabled or total <= 0:
            return
        frac = done / total
        filled = int(self.width * frac)
        bar = "#" * filled + "-" * (self.width - filled)
        sys.stderr.write(f"\r  {prefix}[{bar}] {done}/{total} ({frac*100:5.1f}%)")
        sys.stderr.flush()

    def done(self):
        if self.enabled:
            sys.stderr.write("\n")
            sys.stderr.flush()


# --------------------------------------------------------------------------- #
#  Secuencial global + log de ejecución
# --------------------------------------------------------------------------- #
class ExecLog:
    """
    Numera cada ejecución con un secuencial global (hilo-seguro) y la
    registra en un archivo de log: fecha/hora | #seq | target | tipo |
    método | status | nivel | payload.
    """
    def __init__(self, path: Optional[str]):
        self._lock = threading.Lock()
        self._seq = 0
        self.path = path
        self._fh = None
        if path:
            try:
                self._fh = open(path, "a", encoding="utf-8")
                self._fh.write("# " + "=" * 78 + "\n")
                self._fh.write(f"# Inicio de ejecución: "
                               f"{datetime.datetime.now().isoformat(timespec='seconds')}\n")
                self._fh.write("# fecha/hora | #seq | target | tipo | metodo | "
                               "status | nivel | payload\n")
                self._fh.write("# " + "=" * 78 + "\n")
                self._fh.flush()
            except OSError as e:
                sys.exit(f"[!] No se pudo abrir el log '{path}': {e}")

    def record(self, target: str, tipo: str, res: Result, level: str) -> int:
        """Asigna secuencial, escribe la línea de log y devuelve el número."""
        with self._lock:
            self._seq += 1
            seq = self._seq
            status = str(res.status) if res.status else "ERR"
            payload = res.payload or res.url
            if self._fh:
                self._fh.write(
                    f"{res.ts} | #{seq:05d} | {target} | {tipo} | "
                    f"{res.method} | {status} | {LEVEL_TAG.get(level, level).strip()} | "
                    f"{payload}\n"
                )
                self._fh.flush()
            return seq

    def footer(self, stats: dict):
        if not self._fh:
            return
        with self._lock:
            self._fh.write("# " + "-" * 78 + "\n")
            for k, v in stats.items():
                self._fh.write(f"# {k}: {v}\n")
            self._fh.write("# " + "=" * 78 + "\n\n")
            self._fh.flush()

    def close(self):
        if self._fh:
            self._fh.close()


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


def classify_method(res: Result) -> Tuple[str, List[str], str, str]:
    """
    Devuelve (nivel, notas, justificación, remediación).
    justificación y remediación se completan para hallazgos Alto/Medio.
    """
    notes: List[str] = []
    whys: List[str] = []
    fixes: List[str] = []
    level = "info"

    if res.error:
        return "error", [res.error], "", ""

    code = res.status or 0
    accepted = code < 400 or code in (401, 403)

    if res.method in DANGEROUS_METHODS and code < 400:
        level = "high"
        notes.append(f"Método peligroso {res.method} aceptado (status {code}).")
        if res.method == "CONNECT":
            whys.append(f"El servidor respondió {code} a CONNECT. CONNECT solicita abrir "
                        f"un túnel TCP; si el host lo acepta puede ser abusado como proxy "
                        f"para pivotar hacia otros servicios internos (SSRF/relay). "
                        f"Verifica que la respuesta provenga del servidor y no de un proxy "
                        f"intermedio, que respondería CONNECT por su cuenta.")
        else:
            whys.append(f"El método {res.method} permite crear, modificar o eliminar "
                        f"recursos; un {code} indica que está habilitado y podría permitir "
                        f"alteración no autorizada de datos o archivos en el servidor.")
        fixes.append(f"Deshabilitar {res.method} si el servicio no lo requiere "
                     f"(para SOAP suele bastar POST); restringir los verbos permitidos "
                     f"en el servidor/WAF y exigir autenticación y autorización por método.")

    if res.method == "TRACE" and code == 200:
        level = "high"
        notes.append("TRACE habilitado: posible Cross-Site Tracing (XST).")
        whys.append("TRACE refleja la petición completa; combinado con otras fallas "
                    "permite Cross-Site Tracing (XST) y exfiltrar cabeceras o cookies.")
        fixes.append("Deshabilitar TRACE en el servidor (p. ej. 'TraceEnable Off' en "
                     "Apache, o bloquear el verbo en IIS/Nginx).")

    if res.method == "OPTIONS" and code < 400:
        allow = res.resp_headers.get("Allow") or res.resp_headers.get("Access-Control-Allow-Methods")
        if allow:
            notes.append(f"OPTIONS anuncia métodos: {allow}")
            dangerous_adv = DANGEROUS_METHODS & {m.strip().upper() for m in allow.split(",")}
            if dangerous_adv:
                level = "medium" if level == "info" else level
                notes.append(f"Métodos peligrosos anunciados en Allow: {', '.join(sorted(dangerous_adv))}")
                whys.append(f"El servidor anuncia métodos peligrosos "
                            f"({', '.join(sorted(dangerous_adv))}) en la cabecera 'Allow', "
                            f"revelando superficie de ataque y verbos habilitados.")
                fixes.append("Restringir la cabecera 'Allow' a los métodos estrictamente "
                             "necesarios y deshabilitar los peligrosos.")

    if code == 405:
        allow = res.resp_headers.get("Allow")
        if not allow:
            level = "low" if level == "info" else level
            notes.append("405 sin cabecera 'Allow' (mala práctica: no indica métodos válidos).")

    if not accepted and level == "info":
        notes.append(f"Rechazado (status {code}).")

    return level, notes, " ".join(whys), " ".join(fixes)


def header_hygiene(res: Result) -> List[Tuple[str, str, str, str]]:
    """
    Revisa cabeceras de seguridad y de divulgación sobre una respuesta base.
    Cada hallazgo: (nivel, mensaje, justificación, remediación).
    """
    findings: List[Tuple[str, str, str, str]] = []
    h = res.resp_headers

    for sh in SECURITY_HEADERS:
        if sh not in h:
            findings.append(("low", f"Falta cabecera de seguridad: {sh}", "", ""))

    for dh in DISCLOSURE_HEADERS:
        if dh in h:
            findings.append((
                "medium",
                f"Divulgación de tecnología en '{dh}': {h[dh]}",
                f"La cabecera '{dh}: {h[dh]}' revela el producto o versión del servidor, "
                f"facilitando al atacante buscar vulnerabilidades conocidas de ese componente.",
                f"Ocultar o normalizar la cabecera (p. ej. 'ServerTokens Prod' y "
                f"'ServerSignature Off' en Apache, remover 'X-Powered-By', etc.).",
            ))

    # CORS permisivo
    if h.get("Access-Control-Allow-Origin") == "*":
        findings.append((
            "medium",
            "CORS abierto: Access-Control-Allow-Origin: *",
            "Un origen comodín '*' permite que cualquier sitio lea las respuestas del "
            "servicio, con riesgo de fuga de datos si la respuesta contiene información sensible.",
            "Restringir CORS a una lista blanca de orígenes confiables; nunca usar '*' "
            "en servicios con datos sensibles.",
        ))
    if h.get("Access-Control-Allow-Credentials", "").lower() == "true" and \
       h.get("Access-Control-Allow-Origin") == "*":
        findings.append((
            "high",
            "CORS inseguro: credenciales permitidas con origen '*'.",
            "Permitir credenciales (cookies/autenticación) junto con un origen '*' expone "
            "las sesiones de los usuarios a cualquier sitio web.",
            "No combinar 'Access-Control-Allow-Credentials: true' con origen '*'; "
            "especificar orígenes concretos y confiables.",
        ))

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


def classify_traversal(baseline: Result, res: Result) -> Tuple[str, List[str], str, str]:
    """
    Compara una respuesta de traversal contra la baseline usando SOLO
    status + cabeceras (Content-Type, Content-Length).
    Devuelve (nivel, notas, justificación, remediación).
    """
    notes: List[str] = []
    whys: List[str] = []
    fixes: List[str] = []
    if res.error:
        return "error", [res.error], "", ""

    code = res.status or 0
    level = "info"

    FIX_TRAVERSAL = ("Validar y canonicalizar las rutas en el servidor; rechazar "
                     "secuencias '../', '..\\', '%2e%2e' y codificaciones dobles; "
                     "no construir rutas de archivo a partir de entrada del usuario y "
                     "usar listas blancas de recursos con controles de acceso.")

    # Señal 1: cambio de código respecto a baseline hacia un 2xx
    if baseline.status and baseline.status >= 400 and code < 400:
        level = "high"
        notes.append(f"Status cambió {baseline.status} -> {code} con payload traversal.")
        whys.append(f"El payload de recorrido de rutas cambió la respuesta de "
                    f"{baseline.status} (error) a {code} (éxito), lo que sugiere que el "
                    f"servidor procesó la ruta manipulada y podría estar sirviendo archivos "
                    f"fuera del directorio previsto (Path Traversal / LFI).")
        fixes.append(FIX_TRAVERSAL)

    # Señal 2: cambio notable de Content-Length (posible archivo distinto servido)
    if code < 400 and baseline.length and res.length:
        ratio = res.length / max(baseline.length, 1)
        if ratio > 1.5 or ratio < 0.5:
            level = "medium" if level == "info" else level
            notes.append(
                f"Content-Length difiere de baseline "
                f"({baseline.length} -> {res.length})."
            )
            whys.append(f"El tamaño de la respuesta difiere notablemente de la baseline "
                        f"({baseline.length} -> {res.length} bytes), posible señal de que "
                        f"se devolvió un recurso distinto al esperado.")
            fixes.append(FIX_TRAVERSAL)

    # Señal 3: Content-Type sospechoso (text/plain donde la base era xml/json)
    ct_base = (baseline.resp_headers.get("Content-Type") or "").split(";")[0].strip()
    ct_now = (res.resp_headers.get("Content-Type") or "").split(";")[0].strip()
    if ct_base and ct_now and ct_base != ct_now:
        level = "medium" if level == "info" else level
        notes.append(f"Content-Type cambió: {ct_base} -> {ct_now}")
        whys.append(f"El tipo de contenido cambió respecto a la baseline "
                    f"({ct_base} -> {ct_now}), indicio de que el servidor sirvió otro tipo "
                    f"de recurso ante la ruta manipulada.")
        fixes.append(FIX_TRAVERSAL)

    # Señal 4: cabeceras típicas de descarga de archivo
    cd = res.resp_headers.get("Content-Disposition")
    if cd and code < 400:
        level = "high"
        notes.append(f"Content-Disposition presente: {cd}")
        whys.append("La aparición de 'Content-Disposition' sugiere que el servidor ofrece "
                    "la descarga de un archivo ante el payload, posible exposición de "
                    "archivos del sistema.")
        fixes.append(FIX_TRAVERSAL)

    if level == "info":
        notes.append(f"Sin anomalía evidente (status {code}).")
    return level, notes, " ".join(whys), " ".join(fixes)


# --------------------------------------------------------------------------- #
#  Confirmación de inyección de comandos (PoC no destructivo)
# --------------------------------------------------------------------------- #
# SOLO comandos de LECTURA e inofensivos, para DEMOSTRAR explotabilidad en un
# pentest autorizado. No se admite ejecución de comandos arbitrarios a propósito.
# Cada comando trae las expresiones regulares que confirman su salida en la
# respuesta (es la única parte del script que inspecciona el body).
CMDI_COMMANDS: Dict[str, List[str]] = {
    "id": [r"uid=\d+\([^)]+\)", r"gid=\d+\("],
    "ip a": [r"\binet\s+\d{1,3}(\.\d{1,3}){3}", r"link/(ether|loopback)",
             r"\d+:\s+\w+:\s+<[A-Z,]+>"],
}

# Plantillas típicas de inyección de comandos en SO. {CMD} se sustituye.
CMDI_TEMPLATES = [
    ";{CMD}",
    "|{CMD}",
    "||{CMD}",
    "&&{CMD}",
    "&{CMD}",
    "`{CMD}`",
    "$({CMD})",
    "\n{CMD}",
    "%0a{CMD}",
    "; {CMD} #",
]


def _inject_value(value: str, payload: str) -> str:
    """Devuelve el valor original con el payload de inyección anexado."""
    return f"{value}{payload}"


def build_cmdi_injections(req: ParsedRequest,
                          commands: List[str]) -> List[dict]:
    """
    Construye los casos de inyección de comandos a partir de la petición.
    Inyecta en: cada parámetro del query string, y cada campo del body
    (urlencoded 'k=v&...') o, para body XML/raw, en el valor de cada elemento
    <tag>valor</tag>. Conserva método y body salvo la parte inyectada.
    Devuelve dicts: {desc, method, url, body, cmd, template}.
    """
    cases: List[dict] = []
    parsed = urllib.parse.urlsplit(req.url)
    body_text = req.body.decode("utf-8", "replace") if req.body else ""

    for cmd in commands:
        for tpl in CMDI_TEMPLATES:
            payload = tpl.replace("{CMD}", cmd)

            # 0) Inyección en el PATH de la URL (p. ej. /ws/op;id, /ws/op%0aid).
            #    Se omiten plantillas con salto de línea crudo, inválido en un path.
            if "\n" not in tpl:
                new_path = parsed.path + payload
                new_url = urllib.parse.urlunsplit(
                    (parsed.scheme, parsed.netloc, new_path, parsed.query, ""))
                cases.append({"desc": f"path {tpl}", "method": req.method,
                              "url": new_url, "body": req.body,
                              "cmd": cmd, "template": tpl})

            # 1) Inyección en parámetros del query string
            if parsed.query:
                pairs = urllib.parse.parse_qsl(parsed.query, keep_blank_values=True)
                for i in range(len(pairs)):
                    newp = list(pairs)
                    k, v = newp[i]
                    newp[i] = (k, _inject_value(v, payload))
                    new_q = urllib.parse.urlencode(newp)
                    new_url = urllib.parse.urlunsplit(
                        (parsed.scheme, parsed.netloc, parsed.path, new_q, ""))
                    cases.append({"desc": f"query[{k}] {tpl}", "method": req.method,
                                  "url": new_url, "body": req.body,
                                  "cmd": cmd, "template": tpl})

            # 2) Inyección en campos de un body urlencoded
            if body_text and "=" in body_text and "<" not in body_text:
                bpairs = urllib.parse.parse_qsl(body_text, keep_blank_values=True)
                for i in range(len(bpairs)):
                    newb = list(bpairs)
                    k, v = newb[i]
                    newb[i] = (k, _inject_value(v, payload))
                    new_body = urllib.parse.urlencode(newb).encode("utf-8")
                    cases.append({"desc": f"body[{k}] {tpl}", "method": req.method,
                                  "url": req.url, "body": new_body,
                                  "cmd": cmd, "template": tpl})

            # 3) Inyección en valores de elementos XML/SOAP <tag>valor</tag>
            if body_text and "<" in body_text:
                def _inj_xml(m):
                    return f"{m.group(1)}{_inject_value(m.group(2), payload)}{m.group(3)}"
                # Inyecta en el PRIMER elemento con texto no vacío (evita explosión de casos)
                new_body_text, n = re.subn(
                    r"(<([A-Za-z_][\w:.-]*)>)([^<>]+)(</\2>)",
                    lambda m: f"{m.group(1)}{_inject_value(m.group(3), payload)}{m.group(4)}",
                    body_text, count=1)
                if n:
                    cases.append({"desc": f"xml-body {tpl}", "method": req.method,
                                  "url": req.url, "body": new_body_text.encode("utf-8"),
                                  "cmd": cmd, "template": tpl})

    return cases


def _extract_evidence(body_text: str, cmd: str, maxlen: int = 160) -> str:
    """Devuelve el primer fragmento del body que coincide con la salida del comando."""
    for rx in CMDI_COMMANDS.get(cmd, []):
        m = re.search(rx, body_text)
        if m:
            start = max(0, m.start() - 10)
            frag = body_text[start:m.end() + 40].replace("\n", " ").strip()
            return (frag[:maxlen] + "…") if len(frag) > maxlen else frag
    return ""


def classify_cmdi(res: Result, body_text: str, cmd: str) -> Tuple[str, List[str], str, str]:
    """
    Confirma ejecución de comandos buscando la salida de 'cmd' en el body.
    Si aparece => ALTO (RCE confirmada). Es la única parte que lee el body.
    """
    if res.error:
        return "error", [res.error], "", ""

    for rx in CMDI_COMMANDS.get(cmd, []):
        if re.search(rx, body_text):
            notes = [f"RCE CONFIRMADA: la salida de '{cmd}' aparece en la respuesta."]
            why = (f"EXPLOTABILIDAD DEMOSTRADA: la respuesta contiene la salida del comando "
                   f"'{cmd}' inyectado, lo que prueba ejecución de comandos del sistema "
                   f"operativo (OS Command Injection / RCE). Un atacante podría ejecutar "
                   f"comandos arbitrarios en el servidor con los privilegios del servicio; "
                   f"por tratarse de explotación confirmada se clasifica como CRÍTICA.")
            fix = ("No pasar entrada del usuario a intérpretes de comandos del sistema; usar "
                   "APIs nativas en lugar de shell; si es inevitable, validar con listas "
                   "blancas estrictas y escapar/parametrizar; ejecutar el servicio con el "
                   "mínimo privilegio y aislarlo (p. ej. contenedor sin shell).")
            return "critical", notes, why, fix

    return "info", [f"Sin evidencia de ejecución de '{cmd}'."], "", ""


# --------------------------------------------------------------------------- #
#  Impresión de hallazgos
# --------------------------------------------------------------------------- #
LEVEL_FMT = {
    "critical": lambda s: C.red(C.bold(s)),
    "high":   lambda s: C.red(s),
    "medium": lambda s: C.yellow(s),
    "low":    lambda s: C.cyan(s),
    "info":   lambda s: C.gray(s),
    "error":  lambda s: C.gray(s),
}
LEVEL_TAG = {
    "critical": "CRÍTICA", "high": "ALTO", "medium": "MEDIO", "low": "BAJO",
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
        threads: int = 1, interval_s: float = 0.0,
        target_name: str = "target",
        elog: Optional["ExecLog"] = None,
        progress: Optional["Progress"] = None,
        do_cmdi: bool = False,
        cmdi_commands: Optional[List[str]] = None,
        show_low: bool = False) -> dict:
    """
    Evalúa un microservicio. Devuelve un dict con los contadores de hallazgos,
    la cantidad de payloads lanzados y el detalle de hallazgos para el informe.
    Los hallazgos de severidad BAJA no se imprimen en terminal (salvo show_low),
    pero sí se registran en el log y el detalle del informe.
    """
    if proxy:
        print(C.gray(f"[*] Tráfico enrutado por proxy: {proxy}"))
    if threads > 1 or interval_s:
        print(C.gray(f"[*] Concurrencia: {threads} hilo(s) por lote, "
                     f"{int(interval_s * 1000)} ms entre lotes"))

    summary_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    launched = 0  # payloads/peticiones lanzadas contra este objetivo
    findings: List[dict] = []  # detalle para el informe CSV/JSON

    def bump(level: str):
        if level in summary_counts:
            summary_counts[level] += 1

    def seqn(tipo: str, res: Result, level: str) -> int:
        """Numera la ejecución y la registra en el log. Devuelve el #seq."""
        if elog:
            return elog.record(target_name, tipo, res, level)
        return 0

    def rec_finding(seq, phase, level, res, summary, why="", fix="", evidence=""):
        """Guarda el hallazgo para el informe CSV/JSON."""
        findings.append({
            "seq": seq, "target": target_name, "phase": phase, "level": level,
            "severidad": LEVEL_TAG.get(level, level).strip(),
            "method": res.method, "status": res.status,
            "payload": res.payload, "summary": summary,
            "justificacion": why, "remediacion": fix, "evidencia": evidence,
            "url": res.url, "fecha": res.ts,
        })

    def show_finding(why: str, fix: str):
        """Imprime justificación y remediación (solo Crítica/Alto/Medio)."""
        if why:
            print(C.gray("             Justificación: ") + why)
        if fix:
            print(C.green("             Remediación : ") + fix)

    print(C.bold("\n=== Petición parseada ==="))
    print(req.summary())

    # Baseline con el método original (secuencial: sirve de referencia para todo)
    baseline = send(get_session(proxy), req.method, req.url, req.headers,
                    req.body, req.verify_tls, timeout, "baseline",
                    payload=f"{req.method} {req.url}")
    launched += 1
    bseq = seqn("baseline", baseline, "info")

    # ---- Higiene de cabeceras sobre la respuesta base ----
    if baseline.error:
        print(C.red(f"\n[!] [#{bseq:05d}] La petición base falló: {baseline.error}"))
    else:
        print(C.bold("\n=== Higiene de cabeceras (respuesta base) ==="))
        print(f"  [#{bseq:05d}] Base: {req.method} -> {baseline.status} {baseline.reason} "
              f"({baseline.length} bytes, {baseline.elapsed_ms} ms)")
        hyg = header_hygiene(baseline)
        if not hyg:
            print(C.green("  Sin observaciones de cabeceras."))
        for level, msg, why, fix in hyg:
            bump(level)
            hseq = seqn("header", baseline, level)   # siempre al log
            rec_finding(hseq, "header", level, baseline, msg, why, fix)
            if level == "low" and not show_low:
                continue  # BAJA: no se imprime en terminal (sí queda en log/informe)
            print(f"  [#{hseq:05d}] {tag(level)} {msg}")
            if level in ("critical", "high", "medium"):
                show_finding(why, fix)

    # ---- Fuzzing de métodos (concurrente) ----
    if do_methods:
        print(C.bold("\n=== Fuzzing de métodos HTTP ==="))

        # CONNECT a través de un proxy no llega al servidor: el proxy (p. ej. Burp)
        # responde él mismo "200 Connection established" para abrir un túnel, lo que
        # produciría un falso positivo. Si hay proxy, se omite CONNECT.
        run_methods = methods
        if proxy and "CONNECT" in methods:
            run_methods = [m for m in methods if m != "CONNECT"]
            print(C.yellow("  [i] CONNECT omitido: con proxy activo lo responde el "
                           "propio proxy (no el servidor). Para probarlo, lánzalo sin proxy."))
            if elog:
                skip_res = Result("method:CONNECT", "CONNECT", req.url, None, "",
                                  CaseInsensitiveDict(), 0, 0,
                                  error="omitido (proxy intercepta CONNECT)",
                                  ts=datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")[:-3],
                                  payload=f"CONNECT {req.url}")
                sseq = elog.record(target_name, "method-skip", skip_res, "info")
                print(C.gray(f"  #{sseq:05d} CONNECT  SKIP (proxy)"))

        def method_worker(m):
            return send(get_session(proxy), m, req.url, req.headers, req.body,
                        req.verify_tls, timeout, f"method:{m}",
                        payload=f"{m} {req.url}")

        prog_cb = (lambda d, t: progress.update(d, t, "métodos ")) if progress else None
        results = execute_concurrent(run_methods, method_worker, threads, interval_s,
                                     on_done=prog_cb, key_fn=lambda m: m)
        if progress:
            progress.done()
        launched += len(run_methods)
        methods = run_methods

        print(C.gray(f"  {'SEQ':>7} {'MÉTODO':8} {'STATUS':6} {'LEN':>8} {'ms':>6}  nivel"))
        for m, res in zip(methods, results):
            level, notes, why, fix = classify_method(res)
            if level in ("critical", "high", "medium", "low"):
                bump(level)
            mseq = seqn("method", res, level)      # siempre al log
            if level in ("critical", "high", "medium", "low"):
                rec_finding(mseq, "method", level, res, "; ".join(notes), why, fix)
            if level == "low" and not show_low:
                continue  # BAJA: no se imprime en terminal
            status_s = str(res.status) if res.status else "ERR"
            lvl_s = tag(level) if level != "info" else ""
            print(f"  #{mseq:05d} {m:8} {status_s:6} {res.length:>8} "
                  f"{res.elapsed_ms:>6}  {lvl_s}")
            for nt in notes:
                col = LEVEL_FMT.get(level, str) if level in ("critical", "high", "medium", "low") else C.gray
                print(col(f"             > {nt}"))
            if level in ("critical", "high", "medium"):
                show_finding(why, fix)

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
                payload, turl = item
                return send(get_session(proxy), trav_method, turl, req.headers,
                            req.body, req.verify_tls, timeout, "traversal",
                            payload=payload)

            prog_cb = (lambda d, t: progress.update(d, t, "traversal ")) if progress else None
            results = execute_concurrent(trav_urls, trav_worker, threads, interval_s,
                                         on_done=prog_cb, key_fn=lambda it: it[0])
            if progress:
                progress.done()
            launched += len(trav_urls)

            sin_anomalia = 0
            for (payload, _turl), res in zip(trav_urls, results):
                level, notes, why, fix = classify_traversal(baseline, res)
                if level in ("critical", "high", "medium", "low"):
                    bump(level)
                tseq = seqn("traversal", res, level)   # siempre al log
                if level in ("critical", "high", "medium", "low"):
                    rec_finding(tseq, "traversal", level, res, "; ".join(notes),
                                why, fix)
                # En terminal solo se muestran hallazgos CRÍTICA/ALTO/MEDIO.
                # Los 'info' (sin anomalía) y los BAJA quedan solo en el log.
                if level in ("info", "low") and not show_low:
                    if level == "info":
                        sin_anomalia += 1
                    continue
                status_s = str(res.status) if res.status else "ERR"
                print(f"  #{tseq:05d} {tag(level)} {status_s:4} payload: {payload}")
                for nt in notes:
                    print(C.gray(f"             > {nt}"))
                if level in ("critical", "high", "medium"):
                    show_finding(why, fix)
            if sin_anomalia and not show_low:
                print(C.gray(f"  ({sin_anomalia} payload(s) sin anomalía — "
                             f"detalle en el log)"))

    # ---- PoC de inyección de comandos (opcional, confirma explotabilidad) ----
    if do_cmdi:
        cmds = cmdi_commands or list(CMDI_COMMANDS.keys())
        print(C.bold("\n=== PoC inyección de comandos (demostración de RCE) ==="))
        print(C.yellow("  [!] Fase ACTIVA: inyecta comandos de lectura ("
                       + ", ".join(cmds) + ") para demostrar explotabilidad."))
        print(C.yellow("      Úsala solo con autorización explícita. Lee el body de la "
                       "respuesta para confirmar la ejecución."))
        cases = build_cmdi_injections(req, cmds)
        if not cases:
            print(C.gray("  No se hallaron puntos de inyección (query/body) en la petición."))
        else:
            def cmdi_worker(case):
                return send(get_session(proxy), case["method"], case["url"],
                            req.headers, case["body"], req.verify_tls, timeout,
                            "cmdi", payload=f"{case['desc']} -> {case['cmd']}",
                            keep_body=True)

            prog_cb = (lambda d, t: progress.update(d, t, "cmdi ")) if progress else None
            results = execute_concurrent(cases, cmdi_worker, threads, interval_s,
                                         on_done=prog_cb,
                                         key_fn=lambda c: f"{c['desc']}|{c['cmd']}|{c['url']}")
            if progress:
                progress.done()
            launched += len(cases)

            confirmados = 0
            for case, res in zip(cases, results):
                level, notes, why, fix = classify_cmdi(res, res.body_text, case["cmd"])
                cseq = seqn("cmdi", res, level)
                if level == "critical":
                    confirmados += 1
                    bump("critical")
                    evid = _extract_evidence(res.body_text, case["cmd"])
                    rec_finding(cseq, "cmdi", level, res, "; ".join(notes),
                                why, fix, evidence=evid)
                    status_s = str(res.status) if res.status else "ERR"
                    print(f"  #{cseq:05d} {tag(level)} {status_s:4} "
                          f"[{case['cmd']}] {case['desc']}")
                    for nt in notes:
                        print(LEVEL_FMT["critical"](f"             > {nt}"))
                    if evid:
                        print(C.gray("             Evidencia: ") + evid)
                    show_finding(why, fix)
            if confirmados == 0:
                print(C.green(f"  Sin RCE confirmada en {len(cases)} inyecciones probadas."))
            else:
                print(C.red(C.bold(f"  >> {confirmados} inyección(es) con RCE CONFIRMADA "
                                   f"(CRÍTICA).")))

    # ---- Resumen de este microservicio ----
    print(C.bold(f"\n=== Resumen: {target_name} ==="))
    print(f"  Hallazgos CRÍTICA: {C.red(C.bold(str(summary_counts['critical'])))}")
    print(f"  Hallazgos ALTO   : {C.red(str(summary_counts['high']))}")
    print(f"  Hallazgos MEDIO  : {C.yellow(str(summary_counts['medium']))}")
    print(f"  Hallazgos BAJO   : {C.cyan(str(summary_counts['low']))} "
          + C.gray("(no impresos; en log/informe)"))
    print(f"  Payloads lanzados: {launched}")
    print()

    return {"target": target_name, "counts": summary_counts, "launched": launched,
            "url": req.url, "findings": findings}


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
    ap.add_argument("--cmdi", action="store_true",
                    help="Fase ACTIVA de PoC: inyecta comandos de lectura no destructivos "
                         "(id, ip a) para demostrar explotabilidad (RCE). Requiere "
                         "autorización explícita. Lee el body de la respuesta para confirmar.")
    ap.add_argument("--cmdi-cmd", action="append",
                    choices=list(CMDI_COMMANDS.keys()),
                    help="Qué comando(s) de prueba usar en la fase --cmdi (repetible). "
                         "Por defecto: todos (id, ip a). Solo comandos de lectura.")
    ap.add_argument("--no-color", action="store_true", help="Desactivar colores.")
    ap.add_argument("--show-low", action="store_true",
                    help="Imprimir también en terminal los hallazgos de severidad BAJA "
                         "(por defecto no se imprimen, pero sí quedan en el log y el informe).")
    ap.add_argument("--log", default=None,
                    help="Ruta del log de ejecución. Por defecto: "
                         "soap_fuzzer_YYYYmmdd_HHMMSS.log en el directorio actual.")
    ap.add_argument("--csv", default=None,
                    help="Ruta del informe CSV de hallazgos. Por defecto: junto al log, "
                         "con extensión .csv.")
    ap.add_argument("--json", default=None, dest="json_path",
                    help="Ruta del informe JSON (estadísticas + resumen + hallazgos). "
                         "Por defecto: junto al log, con extensión .json.")
    ap.add_argument("--no-report", action="store_true",
                    help="No generar los informes CSV/JSON.")
    ap.add_argument("--no-progress", action="store_true",
                    help="Desactivar la barra de progreso.")

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

    # ---- Dedupe: ningún método/payload se evalúa dos veces (preserva orden) ----
    def _dedup(seq: List[str]) -> List[str]:
        vistos, out = set(), []
        for x in seq:
            if x not in vistos:
                vistos.add(x)
                out.append(x)
        return out

    n_met_pre, n_pay_pre = len(methods), len(traversal_payloads)
    methods = _dedup(methods)
    traversal_payloads = _dedup(traversal_payloads)
    if len(methods) < n_met_pre or len(traversal_payloads) < n_pay_pre:
        print(C.gray(f"[*] Duplicados eliminados: "
                     f"{n_met_pre - len(methods)} método(s), "
                     f"{n_pay_pre - len(traversal_payloads)} payload(s)."))

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
        if not args.cmdi:
            c_in = _prompt("  ¿PoC de inyección de comandos (id, ip a) para demostrar "
                           "RCE? Solo con autorización [s/N]: ", "n").lower()
            args.cmdi = c_in in ("s", "si", "sí", "y", "yes")
        if not args.log:
            default_log = datetime.datetime.now().strftime(
                "soap_fuzzer_%Y%m%d_%H%M%S.log")
            l_in = _prompt(f"  Ruta para guardar el log de ejecución "
                           f"[{default_log}]: ", default_log)
            # Si dan solo un directorio existente, se guarda el log ahí dentro.
            if l_in and os.path.isdir(l_in):
                l_in = os.path.join(l_in, default_log)
            args.log = l_in

    threads = max(1, args.threads)
    interval_s = args.interval / 1000.0
    # Compatibilidad: con 1 hilo y sin intervalo, --delay sigue espaciando peticiones.
    if threads == 1 and not interval_s and args.delay:
        interval_s = args.delay

    print(C.gray(f"\n[*] Métodos a fuzzear: {len(methods)} | "
                 f"payloads traversal: {len(traversal_payloads)} | "
                 f"hilos: {threads} | intervalo: {int(interval_s * 1000)} ms"))

    # ---- Log de ejecución y barra de progreso ----
    log_path = args.log or datetime.datetime.now().strftime(
        "soap_fuzzer_%Y%m%d_%H%M%S.log")
    elog = ExecLog(log_path)
    progress = Progress(enabled=not args.no_progress)
    print(C.gray(f"[*] Log de ejecución: {os.path.abspath(log_path)}"))

    # ---- Marcas de tiempo globales ----
    t_start = datetime.datetime.now()
    perf_start = time.perf_counter()

    # ---- Ejecutar cada objetivo ----
    reports: List[dict] = []
    try:
        total = len(targets)
        for idx, (name, req) in enumerate(targets, 1):
            if total > 1:
                print(C.bold(f"\n\n########## [{idx}/{total}] {name} ##########"))
            rep = run(req, methods, args.timeout, args.delay,
                      do_methods=not args.no_methods,
                      do_traversal=not args.no_traversal,
                      proxy=proxy,
                      traversal_payloads=traversal_payloads,
                      threads=threads,
                      interval_s=interval_s,
                      target_name=name,
                      elog=elog,
                      progress=progress,
                      do_cmdi=args.cmdi,
                      cmdi_commands=args.cmdi_cmd,
                      show_low=args.show_low)
            reports.append(rep)
    except KeyboardInterrupt:
        print(C.gray("\n[interrumpido]"))

    # ---- Cierre: marcas de tiempo y totales ----
    t_end = datetime.datetime.now()
    duration = time.perf_counter() - perf_start
    total_launched = sum(r["launched"] for r in reports)
    tot = {"critical": sum(r["counts"].get("critical", 0) for r in reports),
           "high": sum(r["counts"]["high"] for r in reports),
           "medium": sum(r["counts"]["medium"] for r in reports),
           "low": sum(r["counts"]["low"] for r in reports)}

    # ---- Resumen final por microservicio ----
    print(C.bold("\n" + "=" * 68))
    print(C.bold("  RESUMEN FINAL POR MICROSERVICIO"))
    print(C.bold("=" * 68))
    print(C.gray(f"  {'MICROSERVICIO':<28} {'CRIT':>5} {'ALTO':>5} {'MEDIO':>6} "
                 f"{'BAJO':>6} {'PAYLOADS':>9}"))
    for r in reports:
        nm = (r["target"][:26] + "..") if len(r["target"]) > 28 else r["target"]
        c = r["counts"]
        print(f"  {nm:<28} "
              f"{C.red(C.bold(str(c.get('critical', 0)))):>5} "
              f"{C.red(str(c['high'])):>5} "
              f"{C.yellow(str(c['medium'])):>6} "
              f"{C.cyan(str(c['low'])):>6} "
              f"{r['launched']:>9}")
    print(C.gray("  " + "-" * 66))
    print(f"  {'TOTAL':<28} "
          f"{C.red(C.bold(str(tot['critical']))):>5} "
          f"{C.red(str(tot['high'])):>5} "
          f"{C.yellow(str(tot['medium'])):>6} "
          f"{C.cyan(str(tot['low'])):>6} "
          f"{total_launched:>9}")

    # ---- Estadísticas globales de la ejecución ----
    print(C.bold("\n" + "=" * 68))
    print(C.bold("  ESTADÍSTICAS DE EJECUCIÓN"))
    print(C.bold("=" * 68))
    stats = {
        "Fecha/hora inicio": t_start.strftime("%Y-%m-%d %H:%M:%S"),
        "Fecha/hora fin": t_end.strftime("%Y-%m-%d %H:%M:%S"),
        "Duración total": f"{duration:.2f} s ({duration/60:.2f} min)",
        "Microservicios evaluados": len(reports),
        "Payloads/peticiones lanzados": total_launched,
        "Hallazgos CRÍTICA (RCE)": tot["critical"],
        "Hallazgos ALTO": tot["high"],
        "Hallazgos MEDIO": tot["medium"],
        "Hallazgos BAJO": tot["low"],
    }
    for k, v in stats.items():
        print(f"  {k:<30}: {v}")
    print()

    # ---- Cerrar log ----
    elog.footer(stats)
    elog.close()
    print(C.gray(f"[*] Log guardado en: {os.path.abspath(log_path)}"))

    # ---- Informes CSV / JSON ----
    if not args.no_report:
        stem = os.path.splitext(log_path)[0]
        csv_path = args.csv or (stem + ".csv")
        json_path = args.json_path or (stem + ".json")
        all_findings: List[dict] = []
        for r in reports:
            all_findings.extend(r.get("findings", []))
        _write_report_csv(csv_path, reports, all_findings, tot, total_launched)
        _write_report_json(json_path, stats, reports, all_findings)
        print(C.gray(f"[*] Informe CSV : {os.path.abspath(csv_path)}"))
        print(C.gray(f"[*] Informe JSON: {os.path.abspath(json_path)}"))


def _write_report_csv(path: str, reports: List[dict], findings: List[dict],
                      tot: dict, total_launched: int) -> None:
    """Escribe el informe CSV: resumen por microservicio + detalle de hallazgos."""
    try:
        with open(path, "w", encoding="utf-8", newline="") as f:
            w = csv.writer(f)
            # Sección 1: resumen por microservicio
            w.writerow(["# RESUMEN POR MICROSERVICIO"])
            w.writerow(["microservicio", "url", "critica", "alto", "medio",
                        "bajo", "payloads"])
            for r in reports:
                c = r["counts"]
                w.writerow([r["target"], r["url"], c.get("critical", 0), c["high"],
                            c["medium"], c["low"], r["launched"]])
            w.writerow(["TOTAL", "", tot["critical"], tot["high"], tot["medium"],
                        tot["low"], total_launched])
            w.writerow([])
            # Sección 2: detalle de hallazgos
            w.writerow(["# DETALLE DE HALLAZGOS"])
            w.writerow(["seq", "fecha", "microservicio", "severidad", "fase",
                        "metodo", "status", "payload", "resumen", "justificacion",
                        "remediacion", "evidencia", "url"])
            for fd in findings:
                w.writerow([fd["seq"], fd["fecha"], fd["target"], fd["severidad"],
                            fd["phase"], fd["method"], fd["status"], fd["payload"],
                            fd["summary"], fd["justificacion"], fd["remediacion"],
                            fd["evidencia"], fd["url"]])
    except OSError as e:
        print(C.yellow(f"[!] No se pudo escribir el CSV '{path}': {e}"))


def _write_report_json(path: str, stats: dict, reports: List[dict],
                       findings: List[dict]) -> None:
    """Escribe el informe JSON completo: estadísticas + resumen + hallazgos."""
    data = {
        "estadisticas": stats,
        "microservicios": [
            {"microservicio": r["target"], "url": r["url"],
             "counts": r["counts"], "payloads": r["launched"]}
            for r in reports
        ],
        "hallazgos": findings,
    }
    try:
        with open(path, "w", encoding="utf-8") as f:
            json.dump(data, f, ensure_ascii=False, indent=2)
    except OSError as e:
        print(C.yellow(f"[!] No se pudo escribir el JSON '{path}': {e}"))


if __name__ == "__main__":
    main()
