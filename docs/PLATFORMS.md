# ADMapper — Guía multiplataforma

> **Análisis técnico:** qué es portable y qué no → **[COMPATIBILITY.md](COMPATIBILITY.md)**  
> Este documento cubre **cómo instalar** en cada SO.

ADMapper es un **script Python** (`pip install` → comando `admapper`). Funciona en **macOS**, **Linux** y **Windows** con Python 3.11+.

## Rutas comunes

| Recurso | macOS / Linux | Windows |
|---|---|---|
| Config | `~/.admapper/` | `%USERPROFILE%\.admapper\` |
| Wordlists | `~/.admapper/wordlists/rockyou.txt` | `%USERPROFILE%\.admapper\wordlists\rockyou.txt` |
| Workspaces | `~/.admapper/workspaces/` (default) | Igual |
| Workspaces (override) | `admapper -O <path>` · `set workspaces <path>` · `$ADMAPPER_WORKSPACES` | Igual |
| Historial REPL | `~/.admapper/history` | `%USERPROFILE%\.admapper\history` |

Comando útil dentro del shell:

```
(admapper)> platform
```

Muestra el SO detectado, rutas y herramientas opcionales encontradas en PATH.

---

## macOS

### Requisitos

- Python 3.11+ (`python3 --version`)
- Xcode CLI tools (para algunas deps): `xcode-select --install`

### Instalación (recomendada — global, sin activar venv)

```bash
cd admapper
./scripts/install.sh    # pipx → admapper en PATH en todas las terminales
# equivalente: make install
```

Reinstalar tras cambios en el código: `./scripts/install.sh --force` o `make reinstall`.

### Instalación desarrollo (venv)

```bash
./scripts/install.sh --venv
source .venv/bin/activate
admapper start
```

Extras dev (pytest, ruff): `./scripts/install.sh --dev`

### Herramientas opcionales (Homebrew)

```bash
brew install hashcat john-jumbo rust python@3.13
# NetExec (nxc) — pipx usa 3.14 por defecto; aardwolf requiere ≤3.13
pipx install --python python3.13 git+https://github.com/Pennyw0rth/NetExec
# Impacket ya viene con pip install -e ".[recon]"

mkdir -p ~/.admapper/wordlists
cp /path/to/rockyou.txt ~/.admapper/wordlists/
```

Homebrew en Apple Silicon instala en `/opt/homebrew/bin`; ADMapper busca ahí automáticamente si no está en PATH.

### Kerbrute en macOS

```bash
# Opción 1: release binary en PATH
# Opción 2: go install github.com/ropnop/kerbrute@latest
```

---

## Windows

### Requisitos

- Python 3.11+ desde [python.org](https://www.python.org/downloads/) o Microsoft Store
- Marcar **"Add Python to PATH"** en el instalador

### Instalación

```powershell
cd admapper
python -m venv .venv
.\.venv\Scripts\activate
pip install -e ".[dev,recon]"
admapper start
```

### Herramientas opcionales

| Herramienta | Instalación típica |
|---|---|
| Impacket | `pip install impacket` (dentro del venv activado) |
| NetExec | `pip install netexec` → scripts en `.venv\Scripts\` |
| hashcat | Binarios desde hashcat.net → añadir carpeta al PATH |
| john | John the Ripper Jumbo → `john.exe` en PATH |
| kerbrute | Descargar `kerbrute_windows_amd64.exe` → renombrar a `kerbrute.exe` en PATH |

Wordlist:

```powershell
mkdir $env:USERPROFILE\.admapper\wordlists
copy rockyou.txt $env:USERPROFILE\.admapper\wordlists\
```

### Notas Windows

- El core (LDAP, DNS, CLI) funciona sin herramientas externas.
- Impacket/NetExec deben estar en el **mismo venv activado** o en PATH del sistema.
- ADMapper oculta ventanas de consola extra al lanzar subprocess (`CREATE_NO_WINDOW`).
- En engagements remotos (VPN), ejecutar desde **Windows Terminal** o PowerShell 7.

---

## Linux (Kali / Debian / Parrot)

```bash
sudo apt install python3-venv seclists hashcat john
cd admapper && python3 -m venv .venv && source .venv/bin/activate
pip install -e ".[dev,recon]"
admapper start
```

Wordlists estándar: `/usr/share/wordlists/rockyou.txt` (symlink en Kali).

---

## Resolución de herramientas

ADMapper busca binarios en este orden:

1. `PATH` del sistema
2. Carpeta `bin`/`Scripts` del Python/venv activo
3. Rutas conocidas por SO (Homebrew, `Program Files`, etc.)

Si una herramienta no aparece en `platform`, revisa PATH o instálala según la tabla de tu SO.
