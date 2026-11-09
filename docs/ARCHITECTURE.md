# Architecture & Defense-in-Depth Profile

English · [Español](#español)

Reference architecture for running three isolated workloads (**multi-tenant PHP panel**, **Node.js web application**, and **24/7 Python background worker**) on a single 2 GB RAM Ubuntu 24.04 LTS VPS.

---

## 1. Perimeter & Network Security

```text
[Internet]
    │
    ├── 22/TCP  ───> [UFW + Fail2ban (ufw banaction)] ───> OpenSSH (Keys only, AllowUsers, modern MACs)
    ├── 80/TCP  ───> [Nginx Default Drop 444]         ───> HTTP 301 -> HTTPS (for valid virtual hosts)
    └── 443/TCP ───> [Nginx TLS 1.2 / 1.3 + HSTS]     ───> Reverse Proxy & FastCGI Pools
```

- **Default Catch-All (`return 444`)**: Any HTTP or HTTPS request arriving with a raw IP in the `Host` header or an unrecognized domain is immediately dropped at the TCP level (`return 444`) without leaking server identity.
- **Kernel Network Hardening (`config/sysctl.d/99-security-hardening.conf`)**:
  - `tcp_rfc1337 = 1` (TIME-WAIT assassination protection)
  - `accept_redirects = 0` and `send_redirects = 0` (IPv4 & IPv6 ICMP redirect blocking)
  - `log_martians = 1` (spoofed/unroutable packet logging)

---

## 2. Multi-Tenant PHP-FPM Isolation

| Subdomain | Web Root (`root`) | Dedicated Unix User | FastCGI Socket | `open_basedir` Jail |
| :--- | :--- | :--- | :--- | :--- |
| `panel.example.com` | `/var/www/html` | `www-data` | `php8.5-fpm.sock` | `/var/www/:/etc/webapp/:/tmp/:/proc/` |
| `tenant_a.example.com` | `/var/www/tenant_a` | `tenant_a` | `php8.5-fpm-tenant_a.sock` | `/var/www/tenant_a/:/tmp/` |
| `tenant_b.example.com` | `/var/www/tenant_b` | `tenant_b` | `php8.5-fpm-tenant_b.sock` | `/var/www/tenant_b/:/tmp/` |
| `tenant_c.example.com` | `/var/www/tenant_c` | `tenant_c` | `php8.5-fpm-tenant_c.sock` | `/var/www/tenant_c/:/tmp/` |

### Tenant Containment Controls
1. **`disable_symlinks if_not_owner from=$document_root;`**: Prevents symlink traversal across tenant directories.
2. **Per-Pool `disable_functions`**: Blocks command execution and process manipulation (`exec`, `passthru`, `shell_exec`, `system`, `proc_open`, `popen`, `symlink`, `link`, `pcntl_*`, `dl`, `putenv`, `posix_*`, `curl_exec`).
3. **`pm = ondemand`**: Workers spawn only on traffic and exit after `10s` idle (`pm.max_children = 4`), keeping baseline RAM usage near zero.

---

## 3. Systemd Service Sandboxing

Both `systemd/node-app.service` and `systemd/python-worker.service` enforce strict unit sandboxing:
- Dedicated unprivileged service accounts (`User=nodeapp`, `User=pyworker`).
- `NoNewPrivileges=true`, `ProtectSystem=strict`, `ProtectHome=true`, `PrivateTmp=true`.
- `ProtectKernelTunables=true`, `ProtectKernelModules=true`, `ProtectControlGroups=true`.
- Explicit `ReadWritePaths=` allow-lists and resource caps (`MemoryMax=350M`, `CPUQuota=85%`).

---

## 4. Kernel Auditing (`auditd`)

`config/audit/rules.d/audit.rules` monitors:
- Identity and privilege files (`/etc/passwd`, `/etc/shadow`, `/etc/group`, `/etc/gshadow`, `/etc/sudoers`).
- Application credential stores (`/etc/webapp/credentials.json`, `/etc/webapp/totp_state.json`).
- SSH daemon configuration (`/etc/ssh/sshd_config`, `/etc/ssh/sshd_config.d/`).
- Privilege escalation binaries (`sudo`, `su`) and kernel module loading (`insmod`, `rmmod`).

---

## Español

Arquitectura de referencia para operar tres cargas aisladas (**panel PHP multi-inquilino**, **aplicación web en Node.js** y **worker 24/7 en Python**) sobre un único VPS Ubuntu 24.04 LTS de 2 GB de RAM.

- **Perímetro**: UFW + Fail2ban, SSH solo por llave pública, Nginx con cierre inmediato (`444`) ante cabeceras `Host` desconocidas y TLS 1.2/1.3 con HSTS.
- **Aislamiento por inquilino**: cada tenant tiene su propio usuario Linux, socket y pool PHP-FPM (`ondemand`), jaula `open_basedir`, `disable_symlinks if_not_owner` y bloqueo de funciones de ejecución de comandos.
- **Sandboxing systemd**: `ProtectSystem=strict`, `NoNewPrivileges=true`, `PrivateTmp=true` y cuotas de CPU/RAM (`MemoryMax=350M`, `CPUQuota=85%`).
- **Auditoría (`auditd`)**: vigilancia sobre archivos de identidad, `sudoers`, configuración SSH y almacén de credenciales.
