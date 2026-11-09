# Informe de Auditoría de Seguridad y Remediación (SEC-01 a SEC-33)

**Alcance**: Auditoría de caja blanca (código + configuración) y caja negra (sondeo perimetral) sobre un servidor Linux Ubuntu LTS de 2 GB de RAM que aloja un panel web multi-inquilino en PHP-FPM (`panel.example.com`, `tenant_*.example.com`), una aplicación web en Node.js (`app.example.com`) y un worker en Python.  
**Host de laboratorio sanitizado**: `203.0.113.10` (`*.example.com`) *(los nombres de rutas, archivos internos y parámetros de ejemplo están sanitizados respecto al host real).*

---

## 1. Evolución de las 5 Fases de Hardening

1. **Fase 1 — Perímetro y aislamiento inicial**: Rate limiting por IP real en Nginx, directiva `disable_symlinks if_not_owner` en virtual hosts de inquilinos, bloqueo de funciones de ejecución de comandos (`disable_functions`) en pools de PHP-FPM, sanitización de archivos SVG subidos y cabeceras `Content-Security-Policy`.
2. **Fase 2 — Autenticación, Anti-Replay y extracción de secretos**: Lista blanca de extensiones y bloqueo de dotfiles en el endpoint de despliegue, bloqueo atómico (`flock`) Anti-Replay para códigos TOTP 2FA (RFC 6238), extracción de credenciales fuera del web root, *backoff* progresivo en intentos de login, protección Anti-CSRF en cierre de sesión y deshabilitación de contraseñas SSH.
3. **Fase 3 — Memoria, sesiones e inspección del DOM**: Eliminación de secretos 2FA y códigos QR pasivos del DOM HTML, activación de `session.use_strict_mode = 1` contra fijación de sesión y aprovisionamiento de memoria Swap (2 GB) para prevenir muertes abruptas por *Linux OOM Killer*.
4. **Fase 4 — Cierre del bloque Catch-All y cuotas Anti-DoS**: Corrección de fuga crítica en el servidor por defecto del puerto 80 (`return 444;`), migración de credenciales a `/etc/webapp/credentials.json` con permisos `0640` (`root:www-data`) y cuotas estrictas de disco e inodos por proyecto.
5. **Fase 5 — Mínimo privilegio, CSP estricta y HTTP/2**: Restricción de telemetría de `/proc` exclusivamente a administradores (acotando a inquilinos a la cuota de su propia carpeta), corrección de cabeceras `X-Frame-Options` duplicadas, mitigación de *Reverse Tabnabbing* (`rel="noopener noreferrer"`), endurecimiento de CSP a `script-src 'self'` sin `'unsafe-inline'`, alojamiento local de activos JS sin `@latest`, habilitación de `http2 on;` y manejo estricto `try_files $uri $uri/ =404;`.

---

## 2. Análisis Técnico de Hallazgos Críticos Destacados

### `SEC-18` (Crítica) — Fuga de archivos por Vhost Catch-All mal configurado en puerto 80
- **Vector detectado**: El bloque `default_server` en el puerto 80 apuntaba a `root /var/www` sin cerrar la conexión ni redirigir antes de evaluar rutas estáticas, permitiendo que una petición HTTP con una cabecera `Host:` arbitraria alcanzara archivos ubicados un nivel por encima de `/var/www/html/`.
- **Remediación**:
  1. Se reemplazaron los bloques `default_server` en los puertos `80` y `443` por cierres inmediatos de conexión a nivel TCP (`return 444;`) ante cualquier `Host` no reconocido o peticiones directas a la IP `203.0.113.10`.
  2. Se reubicó el almacén de credenciales fuera de `/var/www/` hacia `/etc/webapp/credentials.json` (`chown root:www-data`, `chmod 0640`), vigilado mediante reglas del kernel en `auditd` (`-w /etc/webapp/credentials.json -p wa -k app_credentials`).

### `SEC-01` y `SEC-03` — Escape de contenedor lógico entre inquilinos (Cross-Tenant Traversal)
- **Vector detectado**: En un entorno compartido sin contenedores, un inquilino con capacidad de desplegar archivos `.php` podría intentar crear enlaces simbólicos hacia `/var/www/tenant_b/` o ejecutar comandos del sistema (`shell_exec`, `proc_open`, `symlink`) bajo un pool compartido.
- **Remediación en profundidad (3 capas)**:
  1. **Usuario Unix y Pool PHP-FPM dedicado por inquilino**: `tenant_a`, `tenant_b`, `tenant_c`, cada uno con su propio socket Unix (`/run/php/php8.5-fpm-tenant_a.sock`) y permisos de directorio `0750`.
  2. **Jaula `open_basedir` por pool**: `php_admin_value[open_basedir] = /var/www/tenant_a/:/tmp/`.
  3. **Bloqueo en Nginx y PHP-FPM**: `disable_symlinks if_not_owner from=$document_root;` en Nginx y deshabilitación de `exec,passthru,shell_exec,system,proc_open,popen,symlink,link,pcntl_*,dl,putenv,posix_*,curl_exec` en cada pool.

### `SEC-02` y `SEC-07` — Evasión de Rate-Limiting y Reutilización Concurrente de TOTP
- **Vector detectado**:
  - La lectura directa de `HTTP_X_FORWARDED_FOR` en PHP permitía falsificar la IP de origen enviando cabeceras manipuladas para evadir el bloqueo por fuerza bruta.
  - Un código TOTP de 6 dígitos válido durante su ventana de 30 segundos podía reutilizarse en una segunda sesión si el chequeo Anti-Replay vivía únicamente en `$_SESSION`.
- **Remediación**:
  - Uso exclusivo de `$_SERVER['REMOTE_ADDR']` entregado por el socket local de Nginx junto con zonas `limit_req_zone $binary_remote_addr` en Nginx.
  - Registro atómico con bloqueo exclusivo de archivo (`flock(LOCK_EX)`) del par `usuario + time_slice` consumido, rechazando cualquier segundo intento dentro de la ventana de validez.

---

## 3. Matriz Consolidada de Hallazgos (`SEC-01` a `SEC-33`)

| ID | Componente | Vulnerabilidad / Hallazgo | Severidad | Impacto Potencial | Estado |
|:---|:---|:---|:---:|:---|:---:|
| **SEC-01** | Nginx Vhosts | Ausencia de `disable_symlinks` en inquilinos | **MEDIA** | Lectura de archivos de otros inquilinos mediante enlaces simbólicos | Resuelto |
| **SEC-02** | Auth Handler | Spoofing de IP mediante cabecera `X-Forwarded-For` | **MEDIA** | Evasión del limitador de intentos fallidos de login | Resuelto |
| **SEC-03** | PHP-FPM Pools | Funciones de ejecución del SO habilitadas en inquilinos | **BAJA** | Ejecución de comandos del sistema desde scripts PHP | Resuelto |
| **SEC-04** | Deploy Endpoint | Vector Stored XSS mediante archivos SVG | **BAJA** | Ejecución de JavaScript incrustado en imágenes vectoriales | Resuelto |
| **SEC-05** | Cabeceras HTTP | Ausencia de `Content-Security-Policy` en el panel | **BAJA** | Carga de scripts externos no autorizados | Resuelto |
| **SEC-06** | Deploy Endpoint | Validación incompleta de dobles extensiones y dotfiles | **MEDIA** | Subida de scripts ejecutables (`.php.jpg`, `.phar`, `.sh`) | Resuelto |
| **SEC-07** | Auth Handler | Anti-Replay de TOTP limitado a la sesión local | **MEDIA** | Reutilización concurrente de códigos TOTP interceptados | Resuelto |
| **SEC-08** | Auth Handler | Almacén de credenciales dentro del web root | **MEDIA** | Exposición de hashes y secretos en respaldos web | Resuelto |
| **SEC-09** | Auth Handler | Ventana fija en Rate Limiting sin backoff progresivo | **BAJA** | Fuerza bruta espaciada sobre cuentas conocidas | Resuelto |
| **SEC-10** | Logout Flow | Cierre de sesión por GET sin validación de origen | **BAJA** | Logout-CSRF forzado desde sitios externos | Resuelto |
| **SEC-11** | SSH (`sshd_config`) | Directiva `PermitRootLogin yes` activa | **INFO** | Desviación de línea base CIS (cambiado a `prohibit-password`) | Resuelto |
| **SEC-12** | Frontend Auth JS | Credenciales de prueba/producción en JS cliente | **CRÍTICA** | Compromiso de cuentas desde el código fuente del navegador | Resuelto |
| **SEC-13** | Panel UI | Renderizado pasivo de secretos 2FA en el DOM | **ALTA** | Extracción de semillas TOTP desde caché HTML | Resuelto |
| **SEC-14** | PHP-FPM | Directiva `session.use_strict_mode = Off` | **MEDIA** | Aceptación de IDs de sesión no inicializados (Session Fixation) | Resuelto |
| **SEC-15** | Infraestructura | Servidor de 2 GB RAM sin partición/archivo Swap | **MEDIA** | DoS por activación del OOM Killer ante picos de memoria | Resuelto |
| **SEC-16** | Nginx TLS | Ausencia de directivas de sesión TLS endurecidas | **BAJA** | Mayor latencia en handshakes TLS recurrentes | Resuelto |
| **SEC-17** | Web Root | Archivo por defecto de instalación web expuesto | **INFO** | Divulgación de servidor base en rutas por defecto | Resuelto |
| **SEC-18** | Nginx Catch-All | Vhost por defecto en puerto 80 exponía directorio padre | **CRÍTICA** | Fuga de archivos fuera de `html/` mediante cabecera `Host` arbitraria | Resuelto |
| **SEC-19** | Arquitectura | Almacenamiento de secretos dentro de `/var/www/` | **ALTA** | Exposición ante errores de configuración de `root` en Nginx | Resuelto |
| **SEC-20** | Módulo 2FA | Hashes y secretos TOTP de respaldo hardcodeados en código | **ALTA** | Compromiso si el código fuente es compartido o publicado | Resuelto |
| **SEC-21** | Deploy Endpoint | Sin cuota de almacenamiento ni límite de archivos por proyecto | **MEDIA** | Agotamiento de disco o inodos del servidor (Storage DoS) | Resuelto |
| **SEC-22** | Nginx Wildcard | Expresión regular wildcard capturaba subdominios reservados | **MEDIA** | Enrutamiento erróneo de subdominios de sistema al pool wildcard | Resuelto |
| **SEC-23** | Nginx Vhosts | Regla de bloqueo incompleta para `.json`, `.lock`, `.bak`, `.sql` | **BAJA** | Descarga de archivos de configuración o respaldos en inquilinos | Resuelto |
| **SEC-24** | Metrics Endpoint | Omisión de `session.use_strict_mode = 1` en endpoint API | **BAJA** | Inconsistencia en política de sesiones entre páginas y APIs | Resuelto |
| **SEC-25** | Nginx TLS | Avisos de OCSP stapling en certificados sin responder URL | **INFO** | Ruido en bitácoras `/var/log/nginx/error.log` | Resuelto |
| **SEC-26** | Panel UI | Enlaces externos con `target="_blank"` sin `noopener` | **MEDIA** | Vector de Reverse Tabnabbing vía `window.opener` | Resuelto |
| **SEC-27** | Metrics Endpoint | Telemetría global del host visible para usuarios no admin | **MEDIA** | Divulgación de procesos, red y memoria del servidor a inquilinos | Resuelto |
| **SEC-28** | Cabeceras HTTP | Cabeceras `X-Frame-Options` duplicadas (`DENY, SAMEORIGIN`) | **MEDIA** | Interpretación ambigua de protección anti-clickjacking | Resuelto |
| **SEC-29** | Deploy Endpoint | Sin límite en número de proyectos por cuenta | **MEDIA** | Degradación de rendimiento y abuso de almacenamiento | Resuelto |
| **SEC-30** | APIs Backend | Falta de verificación de `maxIdleTime` en llamadas API | **BAJA** | Sesiones inactivas mantenidas vivas mediante polling | Resuelto |
| **SEC-31** | Nginx TLS | Vhosts escuchando en 443 sin `http2 on;` habilitado | **BAJA** | Mayor latencia y ausencia de multiplexación HTTP/2 | Resuelto |
| **SEC-32** | Fail2ban | Umbral de baneo SSH excesivamente bajo sin ventana gradual | **BAJA** | Bloqueos accidentales ante reconexiones legítimas | Resuelto |
| **SEC-33** | Panel UI | Inserción con `innerHTML` en notificaciones dinámicas | **BAJA** | Riesgo de DOM XSS si un mensaje de error contiene HTML | Resuelto |

---

## 4. Verificación Empírica de Sondeo Perimetral (Rutas de Referencia)

Pruebas HTTP automatizadas de control de acceso y bloqueos tras aplicar las 5 fases:

```text
GET /login.php            -> HTTP 200 OK (Punto de entrada público controlado)
GET /auth.php             -> HTTP 302 Found (Redirige a login sin sesión activa)
GET /workspace.php        -> HTTP 302 Found (Requiere sesión autenticada + 2FA verificado)
GET /logout.php           -> HTTP 302 Found (Invalida sesión y limpia cookies)
GET /api/v1/deploy.php    -> HTTP 401 Unauthorized (Rechaza peticiones sin sesión válida)
GET /api/v1/metrics.php   -> HTTP 401 Unauthorized (Rechaza peticiones sin sesión válida)
GET /credentials.json     -> HTTP 403 Forbidden (Bloqueado por regla de extensiones en Nginx)
GET /.totp_state.json     -> HTTP 403 Forbidden (Bloqueado por regla de dotfiles en Nginx)
GET /.env                 -> HTTP 403 Forbidden (Bloqueado por regla de dotfiles en Nginx)
GET /.git/config          -> HTTP 403 Forbidden (Bloqueado por regla de dotfiles en Nginx)
GET /phpinfo.php          -> HTTP 404 Not Found (Inexistente)
Host: 203.0.113.10        -> TCP Connection Closed (Nginx return 444; cero cabeceras devueltas)
Host: unknown.example.com -> TCP Connection Closed (Nginx return 444; cero cabeceras devueltas)
```
