# ADMapper — Análisis de compatibilidad

ADMapper es un **paquete Python** con script de consola (`admapper`). No es un binario nativo ni una app Electron: se instala con pip y corre sobre el intérprete Python del sistema.

```
pip install admapper          # núcleo
pip install "admapper[recon]" # + impacket (SMB/Kerberos/roast)
admapper start                # entry point → admapper.cli.main:app
```

**Requisito único real:** Python **3.11+** en macOS, Linux o Windows.

---

## Tres capas de dependencias

La compatibilidad no es “¿funciona en Windows?” sino **¿qué capa usa cada comando?**

| Capa | Instalación | Qué es | ¿Multiplataforma? |
|---|---|---|---|
| **CORE** | `pip install admapper` | Python puro: ldap3, dnspython, typer, rich, JSON | ✅ Sí — mismo código en los 3 SO |
| **RECON** | `pip install admapper[recon]` | Impacket como librería + subprocess con `sys.executable` | ✅ Sí* — pip wheel; en Windows a veces hace falta MSVC runtime |
| **EXTERNAL** | Instalación manual del usuario | hashcat, john, kerbrute, nxc (binarios Go/C) | ⚠️ Depende del SO — **no van en el paquete pip** |

\* Impacket en Windows: funcional para la mayoría de flujos ADMapper; SMB avanzado puede requerir entorno bien configurado (venv activo, red/VPN).

---

## Matriz por comando

| Comando | Capa mínima | Runtime | macOS | Linux | Windows |
|---|---|---|---|---|---|
| `admapper start` | CORE | Python | ✅ | ✅ | ✅ |
| `start_unauth` | CORE | dnspython + socket | ✅ | ✅ | ✅ |
| `enum users` (LDAP) | CORE | ldap3 | ✅ | ✅ | ✅ |
| `enum users` (SAMR/RID) | RECON | impacket import | ✅ | ✅ | ✅* |
| `asreproast` / `kerberoast` | RECON | impacket subprocess | ✅ | ✅ | ✅* |
| cracking automático | EXTERNAL | hashcat/john | ✅† | ✅† | ✅† |
| `spray` (por defecto) | CORE | ldap3 bind | ✅ | ✅ | ✅ |
| `spray --method kerbrute` | EXTERNAL | kerbrute binary | ✅† | ✅† | ✅† |
| `creds verify` (LDAP) | CORE | ldap3 | ✅ | ✅ | ✅ |
| `creds verify` (SMB/KRB) | RECON | impacket | ✅ | ✅ | ✅* |
| `start_auth` | CORE (+RECON opcional) | ldap3 + JSON | ✅ | ✅ | ✅ |

† = requiere binario instalado y en PATH (o en `.venv/Scripts` en Windows).  
\* = con venv activo y `pip install impacket`.

---

## Qué SÍ es portable (diseño actual)

Estas decisiones ya están hechas para un script Python multiplataforma:

1. **`pathlib.Path` + `Path.home()`** — config en `~/.admapper/` (Windows: `%USERPROFILE%\.admapper\`).
2. **Sin rutas `/usr/...` en lógica crítica** — solo como candidatos opcionales en `find_wordlist()`.
3. **Subprocess Impacket con `sys.executable`** — siempre usa el Python/venv activo, no un `python3` hardcodeado.
4. **`resolve_executable()`** — busca PATH → venv `bin`/`Scripts` → Homebrew / Program Files.
5. **Spray por LDAP (ldap3)** — no depende de kerbrute; funciona igual en los 3 SO.
6. **Port scan con `socket`** — stdlib, sin nmap obligatorio.
7. **Estado en JSON** — sin SQLite ni permisos especiales de SO.

---

## Qué NO es portable (y no debe prometerse)

| Elemento | Por qué |
|---|---|
| hashcat / john | Binarios nativos; GPU/drivers distintos por SO |
| kerbrute / nxc | Binarios Go/Python separados; el usuario los instala |
| Wordlists del sistema | `/usr/share/wordlists` solo en Linux/Kali — usar `~/.admapper/wordlists/` |
| “Funciona sin red” | Necesita reachability al DC (VPN, lab, etc.) — independiente del SO |
| BloodHound / binario único | Fase futura; hoy es orquestador Python |

---

## Instalación recomendada por SO

### macOS (tu entorno)

```bash
python3 -m venv .venv && source .venv/bin/activate
pip install -e ".[dev,recon]"
admapper start
(admapper)> platform   # diagnóstico
```

Opcional: `brew install hashcat john-jumbo` — no bloquea el núcleo.

### Linux (Kali / pentest)

```bash
pip install "admapper[recon]"
# wordlists: /usr/share/wordlists o ~/.admapper/wordlists/
```

### Windows

```powershell
python -m venv .venv
.\.venv\Scripts\activate
pip install "admapper[recon]"
admapper start
```

Importante en Windows:

- Activar el **venv** antes de `admapper` para que Impacket y NetExec estén en `Scripts\`.
- `platform` lista qué encuentra en PATH.
- LDAP spray y `start_unauth` funcionan sin binarios extra.

---

## Distribución futura (sin cambiar el modelo)

| Método | Compatibilidad | Notas |
|---|---|---|
| `pip install admapper` | ✅ Referencia | PyPI cuando publiquemos |
| `pipx install admapper` | ✅ Aislado | Bueno para macOS/Linux |
| `uv tool install` | ✅ Aislado | Alternativa moderna |
| PyInstaller / Nuitka | ⚠️ Por SO | Un .exe por Windows, .app por macOS — fase posterior |
| Docker | ✅ Lab | Opcional; no es el camino por defecto |

---

## Comando de diagnóstico

```
(admapper)> platform
```

Muestra: SO, rutas, herramientas EXTERNAL detectadas y matriz de features con tier CORE/RECON/EXTERNAL.

---

## Resumen para el diseño del proyecto

> **ADMapper es multiplataforma porque es Python**, no porque empaquete todos los tools de pentest.
>
> - **Garantizado** con solo pip: CLI, recon LDAP/DNS/TCP, enum LDAP, spray LDAP, verify LDAP, workspaces.
> - **Con `[recon]`**: SAMR, SMB, roast, verify SMB/Kerberos.
> - **Opcional externo**: cracking y spray kerbrute/nxc.
>
> No hace falta código distinto por SO salvo: resolución de PATH, subprocess flags en Windows, y candidatos de wordlist.
