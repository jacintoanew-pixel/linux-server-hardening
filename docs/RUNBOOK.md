# Operations Runbook

English · [Español](#español)

Standard operating procedures for health checks, zero-downtime configuration reloads, Fail2ban management, and audit inspection on the hardened VPS.

---

## 1. Service Health & Resource Checks

```bash
# Verify core services
systemctl is-active nginx php8.5-fpm node-app python-worker fail2ban auditd

# Memory, Swap, and Disk usage
free -h
df -h /
df -i /

# Listening sockets
ss -tulpn | grep -E ':80|:443|:22|:3000'
```

## 2. Zero-Downtime Reloads

```bash
# Validate Nginx syntax before reloading
sudo nginx -t && sudo systemctl reload nginx

# Reload PHP-FPM pools
sudo systemctl reload php8.5-fpm
```

## 3. Fail2ban & Rate-Limit Operations

```bash
# Inspect active SSH bans
sudo fail2ban-client status sshd

# Unban an IP address
sudo fail2ban-client set sshd unbanip <IP_ADDRESS>

# Clear application-level login rate-limit locks (sanitized path)
sudo rm -rf /var/lib/webapp/ratelimit/*
```

## 4. Audit Log Inspection (`auditd`)

```bash
# Search audit events by key
sudo ausearch -k app_credentials -i
sudo ausearch -k sshd_config -i
sudo ausearch -k priv_escalation -i
```

---

## Español

Procedimientos operativos estándar para diagnóstico de salud, recargas sin caída de servicio, administración de Fail2ban y consulta de eventos de `auditd`.

1. **Estado de servicios**: `systemctl is-active nginx php8.5-fpm node-app python-worker fail2ban auditd`
2. **Recarga segura de Nginx**: `sudo nginx -t && sudo systemctl reload nginx`
3. **Desbloqueo en Fail2ban**: `sudo fail2ban-client set sshd unbanip <IP>`
4. **Auditoría del kernel**: `sudo ausearch -k app_credentials -i`
