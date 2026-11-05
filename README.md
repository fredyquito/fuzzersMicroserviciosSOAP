# fuzzersMicroserviciosSOAP
Fuzzer concurrente de métodos HTTP y path traversal para microservicios SOAP/HTTP. Acepta curl o colecciones Postman, enruta por Burp y detecta malas prácticas analizando solo cabeceras y códigos de estado.
# soap_fuzzer

Herramienta de fuzzing para microservicios **SOAP / HTTP**. Toma una petición
—como comando `curl` o desde una colección de **Postman**— y ejecuta pruebas de
seguridad concurrentes, analizando los resultados **únicamente a partir de las
cabeceras de respuesta y los códigos de estado**. El body de la petición se
envía tal cual y el de la respuesta no se altera. Pensada para detectar malas
prácticas de programación y de configuración.

## ¿Qué hace?

1. **Fuzzing de métodos HTTP** — prueba GET, POST, PUT, DELETE, PATCH, OPTIONS,
   HEAD, TRACE, CONNECT (o los que indiques) y marca los métodos peligrosos que
   el servidor acepta, TRACE habilitado (XST), respuestas `405` sin cabecera
   `Allow`, etc.
2. **Path traversal** — inyecta payloads de recorrido de rutas en la URL
   (conservando el método y el body originales de la petición) y detecta
   anomalías comparando contra una petición *baseline*: cambios de status, de
   `Content-Type`, de `Content-Length` o aparición de `Content-Disposition`.
3. **Higiene de cabeceras** — sobre la respuesta base revisa cabeceras de
   seguridad ausentes (HSTS, CSP, X-Content-Type-Options…), divulgación de
   tecnología (`Server`, `X-Powered-By`…) y CORS permisivo.

Al final muestra un resumen de hallazgos por nivel: **ALTO / MEDIO / BAJO**.

## Características

- **Entrada flexible**: comando `curl` (directo, archivo o stdin) o colección
  **Postman v2.0/2.1** (con carpetas anidadas y variables `{{...}}`).
- **Menú interactivo** que configura todo el escenario, o uso por **línea de
  comandos** para automatizar.
- **Listas desde archivos `.txt`**: métodos y payloads de traversal se pueden
  cargar desde ficheros (uno por línea, ignora vacías y comentarios `#`).
- **Concurrencia parametrizable**: N hilos por lote y un intervalo configurable
  entre lotes (p. ej. 10 hilos cada 500 ms) para acelerar sin saturar el
  objetivo.
- **Conserva método y body originales** en todas las pruebas (clave para SOAP,
  que suele requerir POST con un sobre XML).
- **Integración con Burp Suite** vía proxy, para registrar todas las pruebas en
  tu informe.

## Requisitos

```bash
pip install requests
```

## Uso

### Menú interactivo

```bash
python3 soap_fuzzer.py
```

Te pregunta, en orden: fuente (curl o Postman), proxy (Burp u otro), archivo de
métodos, archivo de payloads, hilos e intervalo. Luego ejecuta y resume.

### Línea de comandos

```bash
# curl a través de Burp, 10 hilos concurrentes cada 500 ms
python3 soap_fuzzer.py --curl-file peticion.txt --burp --threads 10 --interval 500

# colección Postman completa
python3 soap_fuzzer.py --postman coleccion.json --burp

# peticiones concretas + variables + listas desde archivos
python3 soap_fuzzer.py --postman coleccion.json --select 1-3 \
    --var baseUrl=https://host --var token=ABC \
    --methods-file metodos.txt --traversal-file payloads.txt \
    --threads 8 --interval 300 --burp
```

### Opciones principales

| Opción | Descripción |
|---|---|
| `--curl` / `--curl-file` / `--stdin` | Entrada como comando curl. |
| `--postman` | Ruta de una colección Postman `.json`. |
| `--select` | Qué peticiones usar: `all`, `1,3,5` o `2-6`. |
| `--var clave=valor` | Resuelve variables de la colección (repetible). |
| `--methods` / `--methods-file` | Métodos por coma, o un archivo `.txt` (uno por línea). |
| `--traversal-file` | Archivo `.txt` con payloads de traversal (uno por línea). |
| `--threads` | Hilos concurrentes por lote (por defecto 1). |
| `--interval` | Milisegundos de espera entre lotes de hilos. |
| `--burp` | Enruta por `http://127.0.0.1:8080` y desactiva verificación TLS. |
| `--proxy URL` | Proxy personalizado. |
| `--timeout` | Timeout por petición (s). |
| `--no-methods` / `--no-traversal` | Omitir una de las fases. |

### Formato de los archivos `.txt`

Una entrada por línea. Se ignoran las líneas vacías y las que empiezan con `#`.

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
# Payloads de path traversal - uno por línea
../../../../etc/passwd
..%2f..%2fetc%2fpasswd
..%252f..%252f..%252fetc%252fpasswd
..\..\..\..\windows\win.ini
/etc/passwd
```
# Path Traversal Payloads — SOAP Microservices (1000)

Colección de **1000 payloads de path traversal (LFI)** orientados a
**microservicios SOAP** desplegados tras **IBM DataPower** y
**balanceadores Linux/Unix** (nginx, HAProxy, Apache, keepalived).

Incluye **100+ payloads reconstruidos a partir de CVEs reales de severidad
alta/crítica**: Apache (CVE-2021-41773 / CVE-2021-42013), FortiOS
(CVE-2018-13379), F5 BIG-IP (CVE-2020-5902, CVE-2022-1388), Citrix
(CVE-2019-19781, CVE-2023-4966), PAN-OS (CVE-2024-3400), WebLogic
(CVE-2020-14882), Jenkins (CVE-2024-23897), Exchange ProxyShell/ProxyNotShell,
Grafana (CVE-2021-43798), Hikvision (CVE-2021-36260), vCenter, Zimbra y más.

## Contenido

| Sección | Vector |
|---|---|
| CVEs alto/crítico | Payloads de PoCs públicos (NVD / Exploit-DB / GitHub) |
| Traversal Unix/Linux | `/etc/passwd`, `nginx.conf`, `haproxy.cfg`, store de DataPower |
| Codificación | URL simple/doble, overlong UTF-8 (capa balanceador) |
| XML/SOAP | Entidades decimales/hex, CDATA, XInclude, XSLT `document()`, `dp:` |
| Null byte / sufijos | Parsers antiguos |
| Windows | `..\`, `%5c`, `::$DATA`, UNC |
| Wrappers | `file://`, `php://filter`, `expect://` |
| Oracle de detección | Diferenciar faults SOAP por existencia/permisos |

## Uso

Compatible con `ffuf`, `wfuzz`, Burp Intruder y cualquier fuzzer HTTP:
inyectar en el elemento SOAP que reciba rutas (`filename`, `filepath`,
`template`, `docId`...).

ffuf -w payloads_traversal_soap_1000.txt -u https://target/soap -d '<soapenv:Envelope ...><filename>FUZZ</filename>...'

## Referencias

- OWASP WSTG-ATHZ-01 — Testing Directory Traversal / File Include
- OWASP Path Traversal Cheat Sheet
- PayloadsAllTheThings / SecLists

## Aviso legal

Solo para uso en sistemas con **autorización escrita** (pentesting, laboratorios,
investigación de seguridad). El usuario es responsable del cumplimiento de las
leyes locales. Los payloads derivados de CVEs son reconstrucciones de PoCs
públicos con fines educativos.

---
Educational purposes only · Authorized testing only

## Cómo analiza (basado en cabeceras)

Cada prueba se evalúa por su **código de estado** y sus **cabeceras de
respuesta**, nunca por el contenido del body. Ejemplos de hallazgos:

- Un método peligroso (PUT/DELETE/TRACE…) que responde `2xx` → **ALTO**.
- `Server` o `X-Powered-By` revelando versiones → **MEDIO**.
- Falta de cabeceras de seguridad → **BAJO**.
- En traversal, un cambio de status a `2xx`, de `Content-Type`/`Content-Length`
  o un `Content-Disposition` respecto a la baseline → señal de posible lectura
  de archivos.

## Aviso legal

Úsala **únicamente** contra sistemas para los que tengas **autorización
explícita**. El uso contra sistemas de terceros sin permiso es ilegal. El autor
no se responsabiliza del mal uso de esta herramienta.
