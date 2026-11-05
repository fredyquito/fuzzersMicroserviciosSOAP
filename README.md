# fuzzersMicroserviciosSOAP

Fuzzer concurrente de **métodos HTTP y path traversal** para microservicios
**SOAP/HTTP** tras **IBM DataPower** y **balanceadores Linux/Unix** (nginx,
HAProxy, Apache, keepalived). Acepta `curl` o colecciones **Postman**, enruta
por **Burp** y detecta malas prácticas analizando **solo cabeceras y códigos
de estado**. Incluye un pack de **1000 payloads de traversal** (100+ basados
en CVEs reales) listo para usar.

---

## Estructura del repositorio

| Archivo | Contenido |
|---|---|
| `soap_fuzzer.py` | El fuzzer (ver abajo) |
| `payloads_traversal_soap_1000.txt` | 1000 payloads de path traversal, 10 secciones |
| `metodos.txt` | 27 métodos HTTP (estándar + WebDAV + propietarios) |
| `traversal_fuzzer_ready.txt` | 818 payloads filtrados, optimizados para `soap_fuzzer.py` |

---

# soap_fuzzer

Herramienta de fuzzing para microservicios **SOAP / HTTP**. Toma una petición
—como comando `curl` o desde una colección de **Postman**— y ejecuta pruebas de
seguridad concurrentes, analizando los resultados **únicamente a partir de las
cabeceras de respuesta y los códigos de estado**. El body de la petición se
envía tal cual y el de la respuesta no se altera.

## ¿Qué hace el script?

`soap_fuzzer.py` es un único script en Python (solo depende de `requests`)
que ejecuta este flujo:

             ┌─────────────────────┐
   curl / Postman│  1. Parseo de la    │  Reconstruye URL, método,
   / menú        │     petición        │  cabeceras, body y TLS
                 └─────────┬───────────┘
                           │
                 ┌─────────▼───────────┐
                 │  2. Baseline        │  Envía la petición original
                 │     (referencia)    │  y audita sus cabeceras
                 └─────────┬───────────┘
                           │
          ┌────────────────┼────────────────┐
          ▼                ▼                ▼
 ┌────────────────┐ ┌───────────────┐ ┌──────────────────┐
 │ 3. Higiene de  │ │ 4. Fuzzing de │ │ 5. Path traversal│
 │    cabeceras   │ │    métodos    │ │   (en la URL)    │
 └────────────────┘ └───────────────┘ └──────────────────┘
          │                │                │
          └────────────────┼────────────────┘
                           ▼
                 ┌─────────────────────┐
                 │ 6. Clasificación    │  ALTO / MEDIO / BAJO
                 │    y resumen        │  por cabeceras/status
                 └─────────────────────┘

1. **Parseo de la entrada.** Convierte un comando `curl` (tokenizado con
   `shlex`, soporta `-X`, `-H`, `-d`/`@file`, `-b`, `-u`, `-A`, `-k`…) o una
   colección **Postman v2.0/v2.1** (carpetas anidadas, bodies raw/urlencoded/
   formdata y variables `{{...}}` resueltas por `--var` o de forma
   interactiva) en una estructura interna `ParsedRequest` (URL, método,
   cabeceras, body, verificación TLS).

2. **Baseline.** Envía la petición original tal cual (con el método y el body
   con los que llegó). Esa respuesta sirve de referencia para todo el análisis
   posterior y además se audita su higiene de cabeceras.

3. **Higiene de cabeceras.** Sobre la baseline detecta: cabeceras de seguridad
   ausentes (HSTS, CSP, X-Content-Type-Options, X-Frame-Options,
   Referrer-Policy, Permissions-Policy), divulgación de tecnología (`Server`,
   `X-Powered-By`, `X-AspNet-Version`, `X-Generator`, `X-Runtime`, `Via`) y
   CORS permisivo (origen `*` y credenciales junto con `*`).

4. **Fuzzing de métodos.** Reenvía la misma petición cambiando solo el verbo
   (lista por defecto o `--methods-file`). Marca: métodos peligrosos aceptados
   (PUT, DELETE, PATCH, TRACE, CONNECT, MOVE, COPY con respuesta `< 400`),
   TRACE habilitado (Cross-Site Tracing), lo anunciado en `Allow`/
   `Access-Control-Allow-Methods` tras `OPTIONS` y respuestas `405` sin
   cabecera `Allow`.

5. **Path traversal.** Genera una URL por payload inyectándolo al final del
   **directorio del path** (conserva query string, método y body originales
   para no romper la semántica SOAP). Cada respuesta se compara contra la
   baseline: cambio de status hacia `2xx`, variación de `Content-Length`
   (>±50%), cambio de `Content-Type` o aparición de `Content-Disposition`
   (indicador de descarga de archivo). **Nunca evalúa el contenido del body.**

6. **Concurrencia y salida.** Ejecuta las pruebas en lotes de N hilos
   (`--threads`) con una pausa configurable entre lotes (`--interval`), usando
   una sesión `requests` por hilo. Soporte de proxy (Burp con `--burp` o
   personalizado con `--proxy`). Al terminar imprime un resumen con el conteo
   de hallazgos por severidad: **ALTO / MEDIO / BAJO**.

## Características

- **Entrada flexible**: `curl` directo, archivo o stdin; colección Postman
  v2.0/2.1 con selección interactiva o por rango (`--select 1-3`).
- **Menú interactivo** que configura todo el escenario, o uso por **línea de
  comandos** para automatizar.
- **Listas desde archivos `.txt`**: métodos y payloads de traversal (uno por
  línea, ignora vacías y comentarios `#`).
- **Concurrencia parametrizable**: N hilos por lote e intervalo entre lotes
  (p. ej. 10 hilos cada 500 ms) para acelerar sin saturar el objetivo.
- **Conserva método y body originales** en todas las pruebas (clave para SOAP,
  que suele requerir POST con un sobre XML).
- **Integración con Burp Suite** vía proxy, para registrar todas las pruebas
  en tu informe.
- **Detección no intrusiva en la lectura**: el análisis se decide por
  status/cabeceras, no por el contenido de las respuestas.

## Requisitos

```bash
pip install requests
Uso
Menú interactivo
python3 soap_fuzzer.py
Línea de comandos — uso recomendado con el pack incluido
# Fuzzing completo con los archivos del repo, vía Burp
python3 soap_fuzzer.py \
  --curl 'curl -X POST https://target/ws/Service.svc -H "Content-Type: text/xml" -H "SOAPAction: \"DownloadFile\"" -d @body.xml' \
  --methods-file metodos.txt \
  --traversal-file traversal_fuzzer_ready.txt \
  --threads 5 --interval 200 --burp

# Colección Postman completa
python3 soap_fuzzer.py --postman coleccion.json --burp

# Selección + variables + listas propias
python3 soap_fuzzer.py --postman coleccion.json --select 1-3 \
    --var baseUrl=https://host --var token=ABC \
    --methods-file metodos.txt --traversal-file payloads.txt \
    --threads 8 --interval 300 --burp
Opciones principales
Opción
--curl / --curl-file / --stdin
--postman
--select
--var clave=valor
--methods / --methods-file
--traversal-file
--threads
--interval
--burp
--proxy URL
--timeout
--no-methods / --no-traversal
Formato de los archivos .txt
Una entrada por línea. Se ignoran las líneas vacías y las que empiezan con #.
# metodos.txt                  # payloads.txt
GET                            ../../../../etc/passwd
PROPFIND                       ..%2f..%2f..%2f..%2fetc%2fpasswd
DEBUG                          ..%252f..%252f..%252fetc%252fpasswd
Nota sobre traversal_fuzzer_ready.txt: el script inyecta el payload
solo en el path de la URL (conservando query string, método y body
originales). Por eso esta lista excluye payloads con ?, #, espacios o
entidades XML (&#47;, CDATA), que no funcionan en esa posición, y conserva
: (wrappers file://) y ; (matrix params tipo Tomcat). Si necesitas los
vectores SOAP/XML completos, usa payloads_traversal_soap_1000.txt con un
fuzzer de body como ffuf/wfuzz o Burp Intruder.
Calibración
- Empieza con --threads 1 para validar que la baseline es estable: el
clasificador de traversal se basa en diferencias contra ella.
- Content-Length idéntico en todas las respuestas suele ser una página de
error genérica del balanceador: prueba los payloads de doble codificación.
- Ajusta --interval al perfil autorizado (200 ms ≈ 5 req/s).
Path Traversal Payloads — SOAP Microservices (1000)
Colección de 1000 payloads de path traversal (LFI) orientados a
microservicios SOAP desplegados tras IBM DataPower y balanceadores
Linux/Unix (nginx, HAProxy, Apache, keepalived).
Incluye 100+ payloads reconstruidos a partir de CVEs reales de severidad
alta/crítica: Apache (CVE-2021-41773 / CVE-2021-42013), FortiOS
(CVE-2018-13379), F5 BIG-IP (CVE-2020-5902, CVE-2022-1388), Citrix
(CVE-2019-19781, CVE-2023-4966 "Citrix Bleeding"), PAN-OS (CVE-2024-3400),
WebLogic (CVE-2020-14882), Tomcat (CVE-2020-9484, Ghostcat), Jenkins
(CVE-2024-23897), Exchange ProxyShell/ProxyNotShell, Grafana (CVE-2021-43798),
Hikvision (CVE-2021-36260), vCenter (CVE-2021-21972), Zimbra, Confluence,
pfSense, WordPress y más.
Secciones del archivo
Sección
1
2
3
4
5
6
7
8
9
Uso con otros fuzzers
ffuf -w payloads_traversal_soap_1000.txt -u https://target/soap \
     -d '<soapenv:Envelope ...><filename>FUZZ</filename>...' \
     -H "Content-Type: text/xml" -mr "root:.*:0:0"
Inyectar en el elemento SOAP que reciba rutas (filename, filepath,
template, docId...).
Cómo clasifica los hallazgos
Señal (solo status + cabeceras)
Método peligroso (PUT/DELETE/TRACE/CONNECT/MOVE/COPY) responde < 400
TRACE habilitado (XST)
CORS con credenciales y origen *
Divulgación de tecnología (Server, X-Powered-By…)
CORS abierto (Access-Control-Allow-Origin: *)
Traversal: status cambia a 2xx vs baseline
Traversal: Content-Disposition presente
Traversal: variación de Content-Length (>±50%) o de Content-Type
405 sin cabecera Allow
Falta de cabeceras de seguridad
Referencias
- OWASP WSTG v4.2 — WSTG-ATHZ-01 (Testing Directory Traversal / File Include)
- OWASP Path Traversal Cheat Sheet
- PayloadsAllTheThings / SecLists
Aviso legal
Herramienta y payloads solo para uso en sistemas con autorización escrita
(pentesting, laboratorios, investigación de seguridad). El uso contra sistemas
de terceros sin permiso es ilegal; el autor no se responsabiliza del mal uso.
Los payloads derivados de CVEs son reconstrucciones de PoCs públicos con fines
educativos.
Educational purposes only · Authorized testing only
