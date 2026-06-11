# ADMapper

Herramienta CLI de pentesting Active Directory — **paquete Python** multiplataforma (macOS, Linux, Windows). Inspirada en [ADScan](https://github.com/ADScanPro/adscan), reconstruida con arquitectura modular.

No es un binario nativo: `pip install` + comando `admapper`. El núcleo (LDAP, DNS, spray, workspaces) es Python puro; Impacket y hashcat son capas opcionales. Ver **[docs/COMPATIBILITY.md](docs/COMPATIBILITY.md)**.

## Estado

✅ **Fase 14 completada** — Fase 15 (MSSQL) en curso

## Documentación

El plan completo del proyecto, fases, técnicas y backlog está en:

**[docs/PROJECT.md](docs/PROJECT.md)**

## Plataformas soportadas

| SO | Estado | Notas |
|---|---|---|
| **macOS** | ✅ soportado | Desarrollo principal; Homebrew + venv; busca `/opt/homebrew/bin` |
| **Linux** | ✅ soportado | Kali/Parrot/Debian — rutas estándar de wordlists |
| **Windows** | ✅ soportado | PowerShell + venv; resuelve `.venv\Scripts\` y `Program Files` |

Requisitos: **Python 3.11+**. Config: `~/.admapper/` (macOS/Linux) o `%USERPROFILE%\.admapper\` (Windows).

- **[docs/COMPATIBILITY.md](docs/COMPATIBILITY.md)** — qué funciona en cada SO y por qué  
- **[docs/PLATFORMS.md](docs/PLATFORMS.md)** — instalación paso a paso

## Instalación

El CLI se registra en `pyproject.toml` → `[project.scripts] admapper` (equivalente moderno a `setup.py` entry_points). **No hace falta `setup.py`.**

### Instalación recomendada (comando global, sin venv)

Una vez, desde la raíz del repo:

```bash
cd admapper
./scripts/install.sh
# o: make install
```

Eso usa **pipx**: `admapper` queda en PATH en **todas** las terminales — sin `source .venv/bin/activate`.

Si `pipx` no está instalado, el script lo instala (Homebrew en macOS). Tras instalar, reinicia la terminal o `source ~/.zshrc`.

```bash
admapper version
admapper run -H 10.129.245.130 -u user -p 'pass' --full
```

Herramientas externas (opcionales, aparte):

```bash
# macOS (Rust required — see NetExec wiki)
brew install rust
# pipx usa Python 3.14 por defecto; aardwolf/PyO3 solo soporta hasta 3.13:
brew install python@3.13
pipx install --python python3.13 git+https://github.com/Pennyw0rth/NetExec
# alternativa si quieres quedarte en 3.14:
# PYO3_USE_ABI3_FORWARD_COMPATIBILITY=1 pipx install git+https://github.com/Pennyw0rth/NetExec

# Linux / fallback
pipx install netexec

brew install hashcat john-jumbo   # macOS
```

NetExec en macOS: [installation-for-mac](https://www.netexec.wiki/getting-started/installation/installation-for-mac)

### Instalación desarrollo (venv)

```bash
./scripts/install.sh --venv
# o: make install-venv
source .venv/bin/activate
```

Con extras de test/lint: `./scripts/install.sh --dev` o `make install-dev`.

**Windows:** `.\scripts\install.ps1` (venv) o `pipx install --editable ".[full]"` para global.

No ejecutes `python3 admapper/cli/run.py` — módulo interno. Usa `admapper` o `python3 -m admapper`.

Engagement sin shell — **solo IP + credenciales** (dominio y DC se infieren en `start_unauth`):

```bash
admapper run -H 10.129.245.130 -u wallace.everette -p 'Welcome2026@' --full
```

El dominio se deduce de LDAP RootDSE (`DC=…`), PTR o DNS. `-w` y `-d` son opcionales (override).

Dependencias: **[docs/DEPENDENCIES.md](docs/DEPENDENCIES.md)**

**macOS (Homebrew):**

```bash
brew install hashcat john-jumbo
pip install -e ".[recon]"    # impacket
mkdir -p ~/.admapper/wordlists && cp rockyou.txt ~/.admapper/wordlists/
```

**Windows (PowerShell):**

```powershell
.\.venv\Scripts\activate
pip install -e ".[dev,recon]"
mkdir $env:USERPROFILE\.admapper\wordlists
```

Dentro del shell: `platform` — muestra SO, rutas y herramientas detectadas.

## Uso rápido

```
(admapper)> set workspace lab
(admapper:lab)> set domain forest.htb
(admapper:lab:forest.htb)> set hosts 10.10.10.0/24
(admapper:lab:forest.htb)> show
(admapper:lab:forest.htb)> creds add alice Secret123!
(admapper:lab:forest.htb)> start_unauth
(admapper:lab:forest.htb)> enum users
(admapper:lab:forest.htb)> asreproast
(admapper:lab:forest.htb)> kerberoast
(admapper:lab:forest.htb)> spray 'Winter2026!'
(admapper:lab:forest.htb)> spray variations
(admapper:lab:forest.htb)> creds verify <id>
(admapper:lab:forest.htb)> start_auth
(admapper:lab:forest.htb)> enum auth
(admapper:lab:forest.htb)> paths
(admapper:lab:forest.htb)> paths show path-001
(admapper:lab:forest.htb)> acls
(admapper:lab:forest.htb)> acls show acl-001
(admapper:lab:forest.htb)> guide acl_abuse
(admapper:lab:forest.htb)> kerberos
(admapper:lab:forest.htb)> kerberos show krb-001
(admapper:lab:forest.htb)> timeroast
(admapper:lab:forest.htb)> guide kerberos_adv
(admapper:lab:forest.htb)> adcs
(admapper:lab:forest.htb)> adcs show adcs-001
(admapper:lab:forest.htb)> guide adcs_esc
(admapper:lab:forest.htb)> coerce
(admapper:lab:forest.htb)> coerce show coerce-001
(admapper:lab:forest.htb)> guide ntlm_relay
(admapper:lab:forest.htb)> postex
(admapper:lab:forest.htb)> postex show postex-001
(admapper:lab:forest.htb)> guide postex_local
(admapper:lab:forest.htb)> mssql
(admapper:lab:forest.htb)> mssql show mssql-001
(admapper:lab:forest.htb)> guide mssql_lateral
(admapper:lab:forest.htb)> cves
(admapper:lab:forest.htb)> cves show cve-001
(admapper:lab:forest.htb)> cves exploit nopac
(admapper:lab:forest.htb)> guide cves_exploit
(admapper:lab:forest.htb)> export
(admapper:lab:forest.htb)> export json
(admapper:lab:forest.htb)> export navigator
```

Cada técnica muestra **guía de explotación manual** (prerequisitos, pasos, comandos) al final del scan — estilo BloodHound.

Roast / SMB / GPP requieren: `pip install -e ".[recon]"` o `.[full]` (ver DEPENDENCIES.md)

## Estructura

```
admapper/
├── admapper/      # código fuente
├── docs/          # documentación
├── tests/         # tests
└── workspaces/    # datos de engagement (gitignored)
```
