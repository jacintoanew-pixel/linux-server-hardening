# INC-002 — Mitigación de Emergencia en PHP-FPM (CVE-2026-109618, CVE-2026-109619 y CVE-2026-115560)

**Severidad máxima**: CVSS v4.0 **9.2 Crítico**  
**Método de aplicación**: Actualización de paquetes + endurecimiento de `php.ini` + `systemctl reload php8.5-fpm` (**cero caída de servicio**)

---

## 1. Análisis de las Vulnerabilidades

| CVE | Vector Técnico | Impacto Potencial |
|---|---|---|
| **CVE-2026-109618** | Corrupción de memoria en el manejador de errores ante condiciones de agotamiento de memoria (*OOM*) en PHP-FPM. | Ejecución remota de código (RCE) no autenticada. |
| **CVE-2026-109619** | Reutilización de estado global liberado (*stale global state*) entre peticiones consecutivas atendidas por un mismo worker FPM. | Fuga de memoria entre peticiones (exposición de tokens de sesión, credenciales o variables de entorno en memoria). |
| **CVE-2026-115560** | Deserialización insegura y corrupción de puntero interno al alterar dinámicamente `session.serialize_handler` vía `ini_set()` mientras `session.upload_progress.enabled` procesa una subida multipart. | Ejecución remota de código (RCE) durante cargas multipart. |

---

## 2. Acciones de Respuesta y Defensa en Profundidad

1. **Actualización de binarios del motor PHP 8.5**:
   - Respaldo preventivo de configuración en `/root/backup_php8.5_fpm_pre_cve_upgrade`.
   - Actualización de `php8.5-fpm`, `php8.5-cli`, `php8.5-common`, `php8.5-curl`, `php8.5-mbstring`, `php8.5-xml` y `php8.5-zip` a la versión parcheada (`8.5.4-0ubuntu1.5`).
2. **Neutralización del vector `upload_progress` (`CVE-2026-115560`)**:
   - Deshabilitación explícita en `/etc/php/8.5/fpm/php.ini`:
     ```ini
     session.upload_progress.enabled = Off
     ```
3. **Verificación de aislamiento entre inquilinos**:
   - Confirmación de que cada inquilino (`tenant_a`, `tenant_b`, `tenant_c`) corre en su propio pool FPM independiente, impidiendo que cualquier condición de memoria residual en un worker de un inquilino cruce hacia el espacio de memoria de otro inquilino o del panel administrativo.

---

## 3. Evidencia de Verificación Post-Parche

| Comprobación | Comando Ejecutado | Resultado Observado |
|---|---|---|
| Versión del paquete instalado | `dpkg -l \| grep php8.5-fpm` | `8.5.4-0ubuntu1.5` |
| Directiva `upload_progress` | `php-fpm8.5 -i \| grep session.upload_progress.enabled` | `session.upload_progress.enabled => Off => Off` |
| Estado del servicio | `systemctl is-active php8.5-fpm` | `active` |
| Sockets de aislamiento por tenant | `ls /run/php/php8.5-fpm-*.sock` | 4 sockets activos (`tenant_a`, `tenant_b`, `tenant_c`, `wildcard`) |
| Sondeo HTTP de servicios | `curl -I https://panel.example.com/login.php` | `HTTP/2 200` |
