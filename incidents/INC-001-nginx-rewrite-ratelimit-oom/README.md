# INC-001 — Mitigación P0 de Evasión de `limit_req` tras `rewrite` en Nginx y Contención OOM en PHP-FPM

**Clasificación**: Parche P0 de Infraestructura (Prevención de Denegación de Servicio / Agotamiento de RAM entre Servicios)  
**Método de aplicación**: Recarga en caliente (`nginx -t && systemctl reload nginx php8.5-fpm`) — **cero peticiones perdidas**

---

## 1. Diagnóstico del Problema

Durante la auditoría del endpoint de sincronización de archivos (`/deploy.php` $\rightarrow$ `/api/v1/deploy.php`, rutas sanitizadas), se identificaron dos vectores combinados que permitían a un atacante o script defectuoso provocar una caída por agotamiento de memoria (*Out-Of-Memory*) sobre otros servicios del mismo VPS (2 GB de RAM):

| ID | Vector | Impacto Real |
|---|---|---|
| **H-1** | Las zonas `limit_req` existentes cubrían únicamente `/login.php` y `/auth.php`. El endpoint de despliegue carecía de limitación de tasa dedicada. | Un cliente podía enviar ráfagas masivas de peticiones de escritura/borrado sin freno en la capa de proxy inverso. |
| **H-2** | El pool `[www]` de PHP-FPM operaba con `memory_limit = -1` (ilimitado) y `max_execution_time = 0` con `pm.max_children = 5`. | Cinco peticiones concurrentes pesadas podían consumir toda la RAM libre del host (2 GB) y disparar el *Linux OOM Killer* contra procesos de otros servicios. |

---

## 2. Análisis Interno de Nginx: Por qué `limit_req` falla dentro de un bloque con `rewrite ... last`

El alias de compatibilidad del endpoint estaba definido así:

```nginx
location = /deploy.php { rewrite ^ /api/v1/deploy.php last; }
```

### Detalle crítico del ciclo de fases de Nginx:
- La directiva `rewrite ... last` se ejecuta en la fase **`NGX_HTTP_FIND_CONFIG_PHASE` / `NGX_HTTP_REWRITE_PHASE`** y fuerza a Nginx a buscar una **nueva `location`** para la URI reescrita (`/api/v1/deploy.php`).
- El módulo `ngx_http_limit_req_module` (`limit_req`) se evalúa más adelante, en la fase **`NGX_HTTP_PREACCESS_PHASE`**, usando únicamente la configuración de la **`location` final** que ganó tras el `rewrite`.
- **Consecuencia**: colocar `limit_req` dentro de `location = /deploy.php` **no aplica ningún límite**, dando una falsa sensación de seguridad.
- **Solución correcta**: declarar una `location` por expresión regular para el destino final (`location ~ ^/api/v1/deploy\.php$`) **antes** del bloque genérico `location ~ \.php$` (ya que Nginx evalúa las `location` regex en orden de aparición y selecciona la primera coincidencia).

---

## 3. Cambios Aplicados (`diff.patch`)

Ver [`diff.patch`](diff.patch) para el parche exacto generado con `diff -u`:

1. **`/etc/nginx/sites-available/default`**:
   - Nueva zona `limit_req_zone $binary_remote_addr zone=deploy_req:10m rate=5r/s;`.
   - Nuevo bloque `location ~ ^/api/v1/deploy\.php$` ubicado antes de `location ~ \.php$` con `limit_req zone=deploy_req burst=15 nodelay;` y `limit_req_status 429;`.
2. **`/etc/php/8.5/fpm/pool.d/www.conf`**:
   - Techo estricto de memoria por worker: `php_admin_value[memory_limit] = 256M`.
   - Techo de tiempo de ejecución: `php_admin_value[max_execution_time] = 60`.

---

## 4. Evidencia de Verificación en Caliente

| Prueba | Resultado Esperado | Resultado Observado |
|---|---|---|
| Validación de sintaxis (`nginx -t`) | `syntax is ok` | `syntax is ok` / `test is successful` |
| Validación de FPM (`php-fpm8.5 -tt`) | Límites reflejados en pool `[www]` | `memory_limit = 256M`, `max_execution_time = 60` |
| Ráfaga de 30 peticiones concurrentes a `/deploy.php` | Activación de `HTTP 429 Too Many Requests` tras el `burst` | `20 × HTTP 401` + `10 × HTTP 429` |
| Petición sin sesión a `/api/v1/deploy.php` | `HTTP 401 Unauthorized` | `HTTP 401 Unauthorized` |
| Continuidad de servicio (PID del proceso maestro PHP-FPM) | Mismo PID antes y después de `systemctl reload` | PID conservado sin interrupción de conexiones |
