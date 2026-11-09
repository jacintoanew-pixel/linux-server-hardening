#!/usr/bin/env bash
# ==============================================================================
# verify-hardening.sh — Script de Auditoría Automatizada de Postura de Seguridad
# ==============================================================================
# Verifica de forma no destructiva los controles de seguridad del servidor:
#   1. Configuración efectiva de OpenSSH (sshd -T)
#   2. Parámetros de red del kernel Linux (sysctl)
#   3. Firewall perimetral (UFW) y prevención de intrusiones (Fail2ban)
#   4. Reglas de auditoría del kernel (auditd)
#   5. Endurecimiento de Nginx (catch-all 444, server_tokens, disable_symlinks)
#   6. Aislamiento de pools PHP-FPM (open_basedir, disable_functions, memory_limit)
# ==============================================================================
set -uo pipefail

PASS_COUNT=0
FAIL_COUNT=0
WARN_COUNT=0

pass() { echo "  [PASS] $1"; PASS_COUNT=$((PASS_COUNT + 1)); }
fail() { echo "  [FAIL] $1"; FAIL_COUNT=$((FAIL_COUNT + 1)); }
warn() { echo "  [WARN] $1"; WARN_COUNT=$((WARN_COUNT + 1)); }

echo "======================================================================"
echo " AUDITORIA DE POSTURA DE SEGURIDAD LINUX (DEFENSE-IN-DEPTH BASELINE)"
echo " Fecha UTC: $(date -u +"%Y-%m-%dT%H:%M:%SZ")"
echo "======================================================================"

# ------------------------------------------------------------------------------
# 1. Auditoría de OpenSSH
# ------------------------------------------------------------------------------
echo ""
echo "[1/6] Verificando configuración efectiva de OpenSSH (sshd -T)..."
if command -v sshd >/dev/null 2>&1; then
    SSHD_CFG=$(sshd -T 2>/dev/null || true)
    if [ -n "$SSHD_CFG" ]; then
        echo "$SSHD_CFG" | grep -q "^passwordauthentication no$" \
            && pass "SSH: PasswordAuthentication = no" \
            || fail "SSH: PasswordAuthentication NO está deshabilitado"

        echo "$SSHD_CFG" | grep -q "^kbdinteractiveauthentication no$" \
            && pass "SSH: KbdInteractiveAuthentication = no" \
            || fail "SSH: KbdInteractiveAuthentication NO está deshabilitado"

        echo "$SSHD_CFG" | grep -qE "^permitrootlogin (prohibit-password|no)$" \
            && pass "SSH: PermitRootLogin restringido (prohibit-password / no)" \
            || fail "SSH: PermitRootLogin permite contraseñas"

        echo "$SSHD_CFG" | grep -q "^allowtcpforwarding no$" \
            && pass "SSH: AllowTcpForwarding = no" \
            || warn "SSH: AllowTcpForwarding no está en 'no'"
    else
        warn "SSH: Ejecuta con sudo para inspeccionar 'sshd -T'"
    fi
else
    warn "SSH: Binario sshd no encontrado"
fi

# ------------------------------------------------------------------------------
# 2. Auditoría de Parámetros de Red del Kernel (sysctl)
# ------------------------------------------------------------------------------
echo ""
echo "[2/6] Verificando parámetros de red del kernel (sysctl)..."
check_sysctl() {
    local key="$1"
    local expected="$2"
    local actual
    actual=$(sysctl -n "$key" 2>/dev/null || echo "N/A")
    if [ "$actual" = "$expected" ]; then
        pass "sysctl: $key = $actual"
    else
        fail "sysctl: $key = $actual (esperado: $expected)"
    fi
}

check_sysctl "net.ipv4.tcp_rfc1337" "1"
check_sysctl "net.ipv4.conf.all.accept_redirects" "0"
check_sysctl "net.ipv4.conf.all.send_redirects" "0"
check_sysctl "net.ipv6.conf.all.accept_redirects" "0"
check_sysctl "net.ipv4.conf.all.log_martians" "1"

# ------------------------------------------------------------------------------
# 3. Firewall (UFW) y Prevención de Intrusiones (Fail2ban)
# ------------------------------------------------------------------------------
echo ""
echo "[3/6] Verificando servicios perimetrales (UFW + Fail2ban)..."
if systemctl is-active --quiet ufw 2>/dev/null; then
    pass "Firewall: servicio ufw activo"
else
    fail "Firewall: servicio ufw NO está activo"
fi

if systemctl is-active --quiet fail2ban 2>/dev/null; then
    pass "IPS: servicio fail2ban activo"
else
    fail "IPS: servicio fail2ban NO está activo"
fi

# ------------------------------------------------------------------------------
# 4. Auditoría del Kernel (auditd)
# ------------------------------------------------------------------------------
echo ""
echo "[4/6] Verificando subsistema de auditoría del kernel (auditd)..."
if systemctl is-active --quiet auditd 2>/dev/null; then
    pass "Auditd: demonio activo"
    if [ -f /etc/audit/rules.d/audit.rules ]; then
        grep -q "/etc/shadow" /etc/audit/rules.d/audit.rules \
            && pass "Auditd: vigilancia sobre /etc/shadow configurada" \
            || fail "Auditd: falta regla para /etc/shadow"
        grep -q "/etc/sudoers" /etc/audit/rules.d/audit.rules \
            && pass "Auditd: vigilancia sobre /etc/sudoers configurada" \
            || fail "Auditd: falta regla para /etc/sudoers"
    fi
else
    warn "Auditd: servicio no activo o no instalado"
fi

# ------------------------------------------------------------------------------
# 5. Controles de Nginx
# ------------------------------------------------------------------------------
echo ""
echo "[5/6] Verificando directivas de seguridad en Nginx..."
if [ -f /etc/nginx/nginx.conf ]; then
    grep -qE "^\s*server_tokens\s+off;" /etc/nginx/nginx.conf \
        && pass "Nginx: server_tokens off activo" \
        || fail "Nginx: server_tokens off NO encontrado en nginx.conf"
fi

if [ -f /etc/nginx/sites-available/default ]; then
    grep -q "return 444;" /etc/nginx/sites-available/default \
        && pass "Nginx: bloque catch-all 'return 444' activo contra Host spoofing" \
        || fail "Nginx: falta cierre 'return 444' en default_server"

    grep -q "disable_symlinks if_not_owner" /etc/nginx/sites-available/default \
        && pass "Nginx: protección anti-symlink traversal ('disable_symlinks if_not_owner') activa" \
        || fail "Nginx: falta 'disable_symlinks if_not_owner'"

    grep -q "http2 on;" /etc/nginx/sites-available/default \
        && pass "Nginx: protocolo HTTP/2 ('http2 on;') habilitado en TLS" \
        || warn "Nginx: 'http2 on;' no encontrado en virtual hosts SSL"

    grep -qE "script-src 'self';" /etc/nginx/sites-available/default \
        && pass "Nginx: CSP estricta (script-src 'self' sin 'unsafe-inline')" \
        || warn "Nginx: revisar directiva script-src en Content-Security-Policy"

    ! grep -qE "try_files\s+\S+\s+\S+\s+/login\.php" /etc/nginx/sites-available/default \
        && pass "Nginx: manejo estricto 404 (sin Soft-404 a login)" \
        || fail "Nginx: posible Soft-404 detectado en try_files"
fi

# ------------------------------------------------------------------------------
# 6. Controles de Aislamiento PHP-FPM
# ------------------------------------------------------------------------------
echo ""
echo "[6/6] Verificando aislamiento y límites en pools PHP-FPM..."
POOL_DIR="/etc/php/8.5/fpm/pool.d"
if [ -d "$POOL_DIR" ]; then
    grep -rq "disable_functions" "$POOL_DIR" \
        && pass "PHP-FPM: bloqueo de funciones de sistema (disable_functions) presente en pools" \
        || fail "PHP-FPM: no se encontró disable_functions en $POOL_DIR"

    grep -rq "memory_limit" "$POOL_DIR" \
        && pass "PHP-FPM: techo de memoria (memory_limit) configurado contra OOM DoS" \
        || fail "PHP-FPM: falta techo memory_limit en $POOL_DIR"
else
    warn "PHP-FPM: directorio $POOL_DIR no presente en este host"
fi

echo ""
echo "======================================================================"
echo " RESUMEN: PASS=$PASS_COUNT | WARN=$WARN_COUNT | FAIL=$FAIL_COUNT"
echo "======================================================================"

exit $((FAIL_COUNT > 0 ? 1 : 0))
