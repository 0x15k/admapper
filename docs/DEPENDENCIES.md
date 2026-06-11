# ADMapper — Dependencias

## Instalación recomendada

```bash
# Desarrollo / pentest completo (recomendado)
pip install -e ".[dev]"

# Solo uso (engagement)
pip install "admapper[full]"

# Mínimo — LDAP/DNS/spray sin SMB/roast
pip install admapper
```

| Extra | Comando pip | Incluye |
|---|---|---|
| *(ninguno)* | `pip install admapper` | CORE: typer, rich, ldap3, dnspython |
| `recon` | `pip install "admapper[recon]"` | + impacket |
| `full` | `pip install "admapper[full]"` | Igual que recon (perfil recomendado) |
| `dev` | `pip install -e ".[dev]"` | + pytest, ruff, impacket |

## Capas vs dependencias

| Capa | Paquetes pip | Binarios externos (no pip) |
|---|---|---|
| CORE | typer, rich, prompt-toolkit, ldap3, dnspython | — |
| RECON | impacket | — |
| EXTERNAL | — | hashcat, john, kerbrute, nxc |

Los binarios EXTERNAL se detectan con `platform` — no se declaran en `pyproject.toml` a propósito.

## Python

- **Mínimo:** 3.11
- **Probado:** 3.11–3.14
- **Distribución:** entry point `admapper` → `admapper.cli.main:main`

## Windows

```powershell
python -m venv .venv
.\.venv\Scripts\activate
pip install -e ".[dev]"
```

Impacket va al venv (`Scripts\`). Activar el venv antes de `admapper start`.

Opcional si SMB falla: `pip install pywin32` (no requerido por defecto).

## macOS

```bash
python3 -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"
```

Opcional vía Homebrew (EXTERNAL): `brew install hashcat john-jumbo`

## Linux (Kali/Debian)

```bash
pip install "admapper[full]"
# wordlists: apt install seclists  OR  ~/.admapper/wordlists/rockyou.txt
```

## Versionado

Dependencias con rangos compatibles semver (`>=X,<Y`) en `pyproject.toml`.  
Impacket fijado a `<0.13` hasta validar API de 0.13+.
