# ADMapper — Compatibilidad, Dependencias y Plataformas

ADMapper es un **paquete Python** con un script de consola (`admapper`). Se instala a través de `pip` y se ejecuta sobre el intérprete de Python del sistema operativo local.

---

## 1. Requisitos y Versiones de Python

- **Versión mínima:** Python 3.11+
- **Versiones probadas:** Python 3.11 a 3.14
- **Entry Point de distribución:** `admapper` -> `admapper.cli.main:main`

---

## 2. Capas de Dependencias (Tiers)

Para facilitar la flexibilidad en diferentes entornos, las dependencias de ADMapper se dividen en extras de `pip`. Esto permite su uso desde escaneos LDAP básicos en entornos restrictivos hasta un toolkit completo con scripts de explotación Kerberos/SMB.

| Extra | Comando pip | Incluye | ¿Multiplataforma? |
|---|---|---|---|
| *(ninguno)* | `pip install admapper` | **CORE**: typer, rich, prompt-toolkit, ldap3, dnspython | ✅ Sí — código puro Python |
| `recon` | `pip install "admapper[recon]"` | **CORE** + **RECON** (impacket) | ✅ Sí* — pip wheel; en Windows requiere MSVC runtime ocasionalmente |
| `full` | `pip install "admapper[full]"` | Igual a `recon` (tier recomendado por defecto) | ✅ Sí |
| `dev` | `pip install -e ".[dev]"` | + pytest, ruff, bandit | ✅ Sí |

> [!NOTE]
> Las dependencias de `pyproject.toml` usan rangos semver compatibles (`>=X,<Y`). Impacket está restringido a `<0.13` para asegurar compatibilidad con su API interna.

---

## 3. Matriz de Compatibilidad por Comando

La disponibilidad de las características de ADMapper en cada plataforma depende de la capa mínima del comando:

| Comando | Capa mínima | Runtime | macOS | Linux | Windows |
|---|---|---|---|---|---|
| `admapper start` | CORE | Python | ✅ | ✅ | ✅ |
| `start_unauth` | CORE | dnspython + socket | ✅ | ✅ | ✅ |
| `enum users` (LDAP) | CORE | ldap3 | ✅ | ✅ | ✅ |
| `enum users` (SAMR/RID) | RECON | impacket | ✅ | ✅ | ✅* |
| `asreproast` / `kerberoast` | RECON | impacket subprocess | ✅ | ✅ | ✅* |
| cracking automático | EXTERNAL | hashcat/john | ✅† | ✅† | ✅† |
| `spray` (por defecto) | CORE | ldap3 bind | ✅ | ✅ | ✅ |
| `spray --method kerbrute` | EXTERNAL | kerbrute binary | ✅† | ✅† | ✅† |
| `creds verify` (LDAP) | CORE | ldap3 | ✅ | ✅ | ✅ |
| `creds verify` (SMB/KRB) | RECON | impacket | ✅ | ✅ | ✅* |
| `start_auth` | CORE | ldap3 + JSON | ✅ | ✅ | ✅ |

† = Requiere binario externo instalado en el PATH.  
\* = Con venv activo y dependencias de `[recon]` instaladas correctamente.

---

## 4. Herramientas Compañeras (Companion Tools)

Algunos de los recursos avanzados de explotación se instalan de forma aislada a través de `pipx` para evitar conflictos en sus árboles de dependencias directas con Impacket:

```bash
pipx install certipy-ad       # Para explotación de AD CS (ESC1-14)
pipx install pywhisker        # Para Shadow Credentials
pipx install netexec          # nxc (Para validación/ejecución remota en SMB/WinRM)
```

---

## 5. Rutas Comunes y Entorno

ADMapper organiza su configuración, wordlists y datos de engagement de forma consistente según el sistema operativo:

| Recurso | macOS / Linux | Windows |
|---|---|---|
| Directorio Config | `~/.admapper/` | `%USERPROFILE%\.admapper\` |
| Wordlists por defecto | `~/.admapper/wordlists/rockyou.txt` | `%USERPROFILE%\.admapper\wordlists\rockyou.txt` |
| Workspaces (Datos) | `~/.admapper/workspaces/` | `%USERPROFILE%\.admapper\workspaces\` |
| Historial REPL | `~/.admapper/history` | `%USERPROFILE%\.admapper\history` |

*Nota: Se puede forzar una ruta de workspaces personalizada mediante la opción global `admapper -O <path>`, configurando `set workspaces <path>` en la consola, o con la variable de entorno `$ADMAPPER_WORKSPACES`.*

---

## 6. Instalación por Plataforma

### macOS
Requiere Xcode Command Line Tools (`xcode-select --install`).

- **Instalación Global (Recomendada via pipx)**:
  ```bash
  cd admapper
  ./scripts/install.sh
  ```
- **Instalación para Desarrollo (venv)**:
  ```bash
  ./scripts/install.sh --venv
  source .venv/bin/activate
  ```
- **Herramientas de red opcionales (Homebrew)**:
  ```bash
  brew install hashcat john-jumbo rust python@3.13
  # Nota: En Apple Silicon se instalan bajo /opt/homebrew/bin
  ```

### Windows
Requiere Python 3.11+ (marcando "Add Python to PATH" en el instalador).

- **Instalación en Entorno Virtual**:
  ```powershell
  cd admapper
  python -m venv .venv
  .\.venv\Scripts\activate
  pip install -e ".[dev,recon]"
  ```
- **Notas de Windows**:
  - Activar el entorno virtual (`.venv`) antes de correr `admapper start` para cargar Impacket y NetExec desde `.venv\Scripts\`.
  - Si experimenta problemas de SMB con scripts locales, instale opcionalmente `pywin32`.

### Linux (Kali / Debian / Parrot)
- **Instalación en Entorno Aislado (venv)**:
  ```bash
  sudo apt install python3-venv seclists hashcat john
  cd admapper
  python3 -m venv .venv
  source .venv/bin/activate
  pip install -e ".[dev,recon]"
  ```

---

## 7. Búsqueda y Resolución de Ejecutables

Al invocar binarios auxiliares (como `nxc`, `certipy`, `faketime`, etc.), ADMapper realiza búsquedas automáticas en el siguiente orden de prioridad:
1. `PATH` del sistema.
2. Carpeta `bin`/`Scripts` del Python/venv activo.
3. Directorios de instalación por defecto del sistema operativo (por ejemplo, `/opt/homebrew/bin` en Apple Silicon de macOS).

Para validar si las herramientas están correctamente mapeadas, ejecute el comando de diagnóstico interactivo:
```
(admapper)> platform
```

---

## 8. Principios de Portabilidad

### Qué SÍ es portable (Core Python):
1. Rutas resueltas via `pathlib.Path` y `Path.home()` (resuelve `%USERPROFILE%` o `/home/` según corresponda).
2. Detección automática de diccionarios de sistema (`/usr/share/wordlists` en Kali vs rutas locales).
3. Persistencia basada en archivos JSON estructurados para evitar la necesidad de bases de datos relacionales dependientes del OS.

### Qué NO es portable (External Binaries):
1. Aceleración por hardware para `hashcat` o `john`.
2. Mapeos de red o adaptadores VPN (el DC debe ser alcanzable por routing de red estándar).
3. Entornos Docker corporativos (ADMapper está diseñado para correr nativamente sin Docker obligatoriamente).
