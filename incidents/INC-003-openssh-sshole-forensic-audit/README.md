# INC-003 — Auditoría Forense de OpenSSH frente a `CVE-2026-123158` (`*sshole`)

**Severidad de la CVE**: CVSS 8.1 (Alta — Omisión de autenticación en configuraciones afectadas)  
**Resultado en el servidor**: **100% Inmune por triple barrera arquitectónica y de configuración**

---

## 1. Mecanismo Técnico de `CVE-2026-123158` (`*sshole`)

1. **Interacción entre OpenSSH y `musl libc` sin PAM**:
   - La vulnerabilidad ocurre cuando `sshd` se compila y enlaza contra la librería estándar de C **`musl libc`** y se ejecuta con **`UsePAM no`** (o sin soporte PAM).
2. **Comportamiento de retorno `"*"` en `musl` `crypt()`**:
   - En `musl libc`, la función `crypt()` rechaza contraseñas de más de **256 bytes** en sus algoritmos SHA-256/SHA-512 y devuelve la cadena literal `"*"` para indicar error (en lugar de `NULL`).
3. **El vector de omisión de autenticación**:
   - En `/etc/shadow`, las cuentas bloqueadas o sin contraseña asignada contienen `"*"` en el campo de hash.
   - Si un atacante envía por SSH una contraseña de entre **257 y 1,024 bytes** hacia un `sshd` sin PAM enlazado con `musl`, `crypt()` falla devolviendo `"*"`, `sshd` compara `"*" == "*"` contra el valor de `/etc/shadow` y concede acceso inmediato a la cuenta.

---

## 2. Verificación Forense en el Servidor

Se ejecutó una inspección directa sobre el binario `/usr/sbin/sshd` y la configuración activa del demonio para verificar cada condición necesaria para la explotación:

```text
                    ┌──────────────────────────────────────────┐
                    │  Intento de Explotación CVE-2026-123158   │
                    │    (Payload de 257–1024 bytes en SSH)    │
                    └────────────────────┬─────────────────────┘
                                         │
        ┌────────────────────────────────┴────────────────────────────────┐
        ▼                                                                 ▼
Barrera 1: Autenticación por Contraseña                           Barrera 2: Librería C del Sistema
┌───────────────────────────────────────────────┐                 ┌───────────────────────────────────────────────┐
│ • PasswordAuthentication = no                 │                 │ • SO: Ubuntu LTS                              │
│ • KbdInteractiveAuthentication = no           │                 │ • libc: GNU C Library (glibc / libc.so.6)     │
│ • PermitRootLogin = prohibit-password         │                 │ • NO enlaza contra musl libc                  │
│ -> sshd rechaza el método password antes de   │                 │ -> No existe el retorno '*' ante entradas     │
│    invocar crypt(); solo acepta publickey.    │                 │    mayores a 256 bytes.                       │
└───────────────────────┬───────────────────────┘                 └───────────────────────┬───────────────────────┘
                        │                                                                 │
                        └────────────────────────────┬────────────────────────────────────┘
                                                     ▼
                                     Barrera 3: Delegación a PAM
                                    ┌─────────────────────────────────────────┐
                                    │ • UsePAM = yes                          │
                                    │ • El flujo de autenticación pasa por    │
                                    │   la pila PAM de Ubuntu, nunca por la   │
                                    │   comparación directa de shadow en sshd.│
                                    └─────────────────────────────────────────┘
```

### Evidencia de comandos ejecutados:

1. **Verificación de la librería C enlazada al binario `sshd`**:
   ```bash
   $ ldd /usr/sbin/sshd | grep libc
   libc.so.6 => /usr/lib/x86_64-linux-gnu/libc.so.6 (GNU C Library)
   ```
   *Resultado*: El binario utiliza **GNU `glibc`**, no `musl libc`.

2. **Verificación de directivas efectivas en ejecución (`sshd -T`)**:
   ```bash
   $ sudo sshd -T | grep -E '^(passwordauthentication|kbdinteractiveauthentication|pubkeyauthentication|permitrootlogin|usepam)'
   passwordauthentication no
   kbdinteractiveauthentication no
   pubkeyauthentication yes
   permitrootlogin prohibit-password
   usepam yes
   ```
   *Resultado*: La autenticación por contraseña está deshabilitada y `UsePAM` está activo. El flujo vulnerable nunca puede ser alcanzado.
