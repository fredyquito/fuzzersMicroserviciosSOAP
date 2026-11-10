# soap_fuzzer

Herramienta de fuzzing para microservicios **SOAP / HTTP**. Toma una petición
—como comando `curl` o desde una colección de **Postman**— y ejecuta pruebas de
seguridad concurrentes, clasificando los hallazgos por severidad y generando un
log de ejecución e informes en CSV/JSON listos para adjuntar a tu reporte.

El análisis de métodos, cabeceras y path traversal se basa **únicamente en las
cabeceras de respuesta y los códigos de estado**; el body de la petición se
envía tal cual (conservando método y cuerpo originales, clave para SOAP). La
única fase que inspecciona el body es la de confirmación de RCE (`--cmdi`),
porque necesita verificar la salida del comando.

> ⚠️ **Uso autorizado únicamente.** Esta herramienta es para pruebas de
> seguridad sobre sistemas para los que tengas **autorización explícita**. El
> uso contra sistemas de terceros sin permiso es ilegal.

---

## ¿Qué hace?

1. **Fuzzing de métodos HTTP** — prueba GET, POST, PUT, DELETE, PATCH, OPTIONS,
   HEAD, TRACE, CONNECT y cualquier verbo que indiques (WebDAV, etc.). Marca
   métodos peligrosos aceptados, TRACE habilitado (XST) y respuestas `405` sin
   cabecera `Allow`.
2. **Path traversal** — inyecta payloads de recorrido de rutas en la URL
   (conservando método y body) y detecta anomalías comparando contra una
   petición *baseline*: cambios de status, de `Content-Type`, de
   `Content-Length` o aparición de `Content-Disposition`.
3. **Higiene de cabeceras** — revisa cabeceras de seguridad ausentes (HSTS,
   CSP, X-Content-Type-Options…), divulgación de tecnología (`Server`,
   `X-Powered-By`…) y CORS permisivo.
4. **PoC de inyección de comandos** (`--cmdi`, opcional) — inyecta comandos de
   lectura no destructivos (`id`, `ip a`) en el path, el query string y el
   body (incluido XML/SOAP), y **confirma RCE** buscando su salida en la
   respuesta.
5. **Inyección en etiquetas** (`--tags`, opcional) — recorre los valores de las
   etiquetas del body XML/SOAP (en `<headerIn>`, `<bodyIn>` o cualquier
   elemento con valor) y prueba:
   - **SQLi** con `' or '1'='1` — comparación diferencial verdadero/falso
     (`'1'='1` vs `'1'='2`) y detección de errores de motor SQL.
   - **Validación de tipo** — inyecta letras y símbolos en los campos numéricos
     para comprobar si el servicio los acepta (falta de validación de entrada).

Cada hallazgo de severidad **Alta/Media/Crítica** incluye una **justificación**
(por qué tiene esa severidad) y una **sugerencia de remediación**.

---

## Severidades

| Severidad   | Cuándo se asigna |
|-------------|------------------|
| **CRÍTICA** | Explotabilidad **demostrada** — RCE confirmada por la fase `--cmdi`. |
| **ALTO**    | Método peligroso aceptado, TRACE/XST, indicio fuerte de path traversal, CORS inseguro, **SQLi (error-based o diferencial de status)**. |
| **MEDIO**   | Divulgación de tecnología, CORS abierto, indicios de traversal, **SQLi booleana por tamaño, campo numérico que acepta letras/símbolos**. |
| **BAJO**    | Cabeceras de seguridad ausentes, `405` sin `Allow`. |

> Los hallazgos **BAJA no se imprimen en terminal** (para reducir ruido), pero
> **sí** se registran en el log y en los informes CSV/JSON. Usa `--show-low`
> para mostrarlos también en pantalla.

---

## Características

- **Entrada flexible**: comando `curl` (directo, archivo o stdin) o colección
  **Postman v2.0/2.1** (carpetas anidadas y variables `{{...}}`).
- **Menú interactivo** que configura todo el escenario, o uso por **línea de
  comandos** para automatizar.
- **Listas desde archivos `.txt`**: métodos y payloads de traversal (uno por
  línea, ignora vacías y comentarios `#`).
- **Concurrencia parametrizable**: N hilos por lote + intervalo configurable
  entre lotes (p. ej. 10 hilos cada 500 ms), con **dedupe** para que ningún
  payload se ejecute dos veces.
- **Conserva método y body originales** en todas las pruebas (SOAP-friendly).
- **Numeración secuencial** de cada ejecución, visible en terminal y log.
- **Barra de progreso** en vivo.
- **Log de ejecución** con `fecha/hora | #seq | target | tipo | método |
  status | nivel | payload`.
- **Informes CSV y JSON** con resumen por microservicio + detalle de hallazgos.
- **Integración con Burp Suite** vía proxy (omite `CONNECT` automáticamente
  cuando hay proxy, para evitar el falso positivo del túnel).

---

## Requisitos

```bash
pip install requests
```

Python 3.8+.

---

## Uso

### Menú interactivo

```bash
python3 soap_fuzzer.py
```

Pregunta, en orden: fuente (curl/Postman), proxy (Burp u otro), archivos `.txt`
de métodos y payloads, hilos, intervalo, PoC de comandos y **la ruta del log**.

### Línea de comandos

```bash
# curl a través de Burp, 10 hilos cada 500 ms
python3 soap_fuzzer.py --curl-file peticion.txt --burp --threads 10 --interval 500

# colección Postman completa, con listas propias y PoC de RCE
python3 soap_fuzzer.py --postman coleccion.json --burp \
    --methods-file metodos.txt \
    --traversal-file path_traversal.txt \
    --cmdi --threads 10 --interval 500 \
    --log auditoria.log
```

### Opciones principales

| Opción | Descripción |
|---|---|
| `--curl` / `--curl-file` / `--stdin` | Entrada como comando curl. |
| `--postman` | Ruta de una colección Postman `.json`. |
| `--select` | Qué peticiones usar: `all`, `1,3,5` o `2-6`. |
| `--var clave=valor` | Resuelve variables de la colección (repetible). |
| `--methods` / `--methods-file` | Métodos por coma, o un archivo `.txt`. |
| `--traversal-file` | Archivo `.txt` con payloads de traversal. |
| `--cmdi` | Fase ACTIVA de PoC de RCE (id, ip a). Solo con autorización. |
| `--cmdi-cmd` | Comando(s) de prueba: `id`, `ip a` (repetible). |
| `--tags` | Fase ACTIVA: SQLi (`' or '1'='1`) y validación de tipo en valores de etiquetas XML. Solo con autorización. |
| `--tags-only` | Limitar `--tags` a ciertas etiquetas (nombres separados por coma, sin namespace). |
| `--sqli-file` | Archivo `.txt` con payloads SQLi (uno por línea). Reemplaza la lista por defecto. |
| `--type-file` | Archivo `.txt` con payloads de validación de tipo (letras/símbolos, uno por línea). |
| `--threads` | Hilos concurrentes por lote (por defecto 1). |
| `--interval` | Milisegundos de espera entre lotes. |
| `--burp` | Enruta por `http://127.0.0.1:8080` y desactiva verificación TLS. |
| `--proxy URL` | Proxy personalizado. |
| `--log` | Ruta del log de ejecución. |
| `--csv` / `--json` | Ruta de los informes (por defecto, junto al log). |
| `--no-report` | No generar los informes CSV/JSON. |
| `--show-low` | Mostrar también los hallazgos BAJA en terminal. |
| `--timeout` | Timeout por petición (s). |
| `--no-methods` / `--no-traversal` | Omitir una de las fases. |
| `--no-progress` / `--no-color` | Desactivar barra de progreso / colores. |

### Formato de los archivos `.txt`

Una entrada por línea. Se ignoran líneas vacías y comentarios (`#`).

**`metodos.txt`**
```
# Métodos HTTP - uno por línea
GET
POST
PUT
DELETE
PROPFIND
```

**`payloads.txt`**
```
# Path traversal - uno por línea
../../../../etc/passwd
..%2f..%2fetc%2fpasswd
..%c0%af..%c0%afetc/passwd
```

**`sqli.txt`** (fase `--tags`, con `--sqli-file`)
```
# Payloads SQLi - uno por línea
' or '1'='1
" or "1"="1
' UNION SELECT NULL--
admin'--
```
> Para cada payload se deriva automáticamente su contraparte falsa
> (`'1'='1` → `'1'='2`) cuando es posible, para la comparación booleana; si no,
> la detección se hace por error SQL o por diferencia contra la baseline.

**`types.txt`** (fase `--tags`, con `--type-file`)
```
# Validación de campos numéricos - uno por línea
ABC
!!!###
12.5
1 OR 1
```

---

## Payloads incluidos

El repositorio incluye diccionarios listos para usar con `--methods-file` y
`--traversal-file`.

### Métodos HTTP (`metodos.txt`)

Conjunto ampliado de verbos, incluyendo WebDAV y verbos no estándar:

```
GET            POST           PUT            DELETE         PATCH
HEAD           OPTIONS        TRACE          CONNECT        PROPFIND
PROPPATCH      MKCOL          COPY           MOVE           LOCK
UNLOCK         SEARCH         REPORT         MERGE          CHECKOUT
CHECKIN        VERSION-CONTROL  DEBUG        PURGE          ACL
BIND           QUERY
```

### Path traversal (`traversal_fuzzer_ready.txt`, `path_traversal_soap_1000.txt`)

Diccionarios de recorrido de rutas orientados a SOAP y a appliances/productos
comunes. Cubren, entre otras, estas categorías (con ejemplos reales de las
listas):

| Categoría | Ejemplo |
|---|---|
| Dot-dot-slash (profundidad 1–8) | `../../../../etc/passwd` |
| Codificación simple y doble | `..%2f..%2fetc%2fpasswd` · `..%252f..%252fetc%252fpasswd` |
| Overlong UTF-8 / Unicode | `..%c0%af..%c0%afetc/passwd` · `..%c1%9c..%c1%9cetc/passwd` |
| Bypass de filtros | `....//....//....//etc/passwd` · `.%2e/.%2e/etc/passwd` |
| Entidades HTML | `..&sol;..&sol;etc&sol;passwd` |
| Null byte / extensión | `../../etc/passwd%00` · `../../etc/passwd%00.php` |
| Rutas de producto / CVE | `/mgmt/tm/util/bash` (F5) · `/vpn/../..%2fcitrix/...ns.conf` (Citrix) · `/global-protect/portal/../../etc/passwd` (PAN) |
| Appliances SOAP / middleware | `../../opt/ibm/datapower/etc/management.cfg` · `../../srv/tomcat/conf/tomcat-users.xml` |
| Windows | `..\..\..\windows\win.ini` · `..%255c..%255c..%255cwindows%255cwin.ini` |
| Wrappers / esquemas | `file:///etc/passwd` · `php://../../etc/passwd` · `expect:///etc/passwd` |
| XML/XXE-style (DataPower) | `document('file:///etc/passwd')` · `dp:open-file('../../../etc/passwd')` |
| Objetivos sensibles | `/etc/passwd`, `/etc/shadow`, `/proc/self/environ`, `root/.ssh/id_rsa`, `WEB-INF/web.xml`, `grafana.ini`, `tomcat-users.xml` |

Uso:

```bash
python3 soap_fuzzer.py --curl-file peticion.txt --burp \
    --methods-file metodos.txt \
    --traversal-file path_traversal_soap_1000.txt
```

> Los diccionarios de traversal son para **lectura de archivos** (detección por
> status/cabeceras). La inyección de comandos para demostrar RCE va por la fase
> `--cmdi`, que confirma la ejecución leyendo la respuesta — no se mezcla en
> estas listas.

---

## Salidas

### Log de ejecución (`.log`)
```
2026-11-08 11:21:31.471 | #00008 | WS-Auth | header    | POST | 200 | MEDIO   | POST http://host/ws
2026-11-08 11:21:31.477 | #00011 | WS-Auth | method    | PUT  | 200 | ALTO    | PUT http://host/ws
2026-11-08 11:21:31.497 | #00027 | WS-Auth | cmdi      | POST | 200 | CRÍTICA | path ;{CMD} -> id
```

### Informe CSV (`.csv`)
Dos secciones: resumen por microservicio (`critica, alto, medio, bajo,
payloads` + TOTAL) y detalle de hallazgos (`seq, fecha, microservicio,
severidad, fase, metodo, status, payload, resumen, justificacion, remediacion,
evidencia, url`).

### Informe JSON (`.json`)
```json
{
  "estadisticas": { "Fecha/hora inicio": "...", "Duración total": "...", "Hallazgos CRÍTICA (RCE)": 0 },
  "microservicios": [ { "microservicio": "...", "counts": {...}, "payloads": 19 } ],
  "hallazgos": [ { "seq": 27, "severidad": "CRÍTICA", "fase": "cmdi", "evidencia": "uid=0(root)...", "...": "..." } ]
}
```

---

## Integración con Burp Suite

Con `--burp` (o `--proxy http://127.0.0.1:8080`) todas las peticiones pasan por
Burp, de modo que tu plugin de reporte las captura. Notas:

- `CONNECT` se **omite automáticamente** cuando hay proxy: el proxy responde él
  mismo `200 Connection established`, lo que sería un falso positivo. Para
  probar `CONNECT` contra el servidor, lánzalo **sin** proxy.
- Para destinos HTTPS, `--burp` desactiva la verificación TLS (Burp usa su
  propia CA).

---

## Aviso legal

Úsala **únicamente** contra sistemas para los que tengas **autorización
explícita**. El uso contra sistemas de terceros sin permiso es ilegal. El autor
no se responsabiliza del mal uso de esta herramienta.
