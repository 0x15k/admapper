# ADMapper — Active Directory Mapping & Pentesting

> Plan maestro del proyecto. Objetivo: replicar y superar lo que hace [ADScan](https://github.com/ADScanPro/adscan), técnica por técnica, en orden de dependencias.

**Estado:** Fases 3, 8.8, 14 (DCSync/postex), PingCastle audits, CLI visual style system, privilege-free clock sync, and worker exception wrapping completed.  
**Referencia analizada:** ADScan v9.x (código + documentación)  
**Última actualización:** 2026-06-25

---

## 1. Visión

Construir una herramienta CLI **multiplataforma** de pentesting Active Directory (macOS, Linux, Windows) que:

1. **Haga lo mismo que ADScan LITE** — enumeración, credenciales, grafo de ataque, explotación guiada.
2. **Sea modular** — cada técnica es un módulo independiente que se apoya en los anteriores.
3. **No dependa de licencias restrictivas** — código propio, licencia permisiva (Apache 2.0 / MIT).
4. **Supere a ADScan** en arquitectura, transparencia y extensibilidad (ver §8).

Flujo objetivo del operador:

```
DNS/SRV → recon sin creds → inventario de usuarios → roast/spray →
auth → colección LDAP/SMB → grafo → rutas de ataque → explotación guiada
```

### Metodología operativa real

La herramienta sigue un orden de dependencias pensado para no saltarse contexto:

1. **Bootstrap / discovery**
   - `set hosts <dc>`
   - `start_unauth`
   - Descubre dominio, DC, puertos, LDAP anónimo, SMB, SPNs, GMSA y señales iniciales.
2. **Recon de usuarios**
   - `enum users`
   - Consolida inventario humano + cuentas de servicio + señales de roast.
3. **Credenciales**
   - `creds add`
   - `creds verify`
   - `asreproast`, `kerberoast`, `spray`
4. **Autenticación / colección ampliada**
   - `start_auth`
   - `enum auth`
   - `acls`
   - `adcs`
   - `coerce`
   - `mssql`
5. **Pivot / post-exploitation**
   - `exploit`
   - `pivot`
   - `winrm`
   - `postex`
6. **Síntesis**
   - `paths`
   - `brief`
   - `export`

### Mapeo CLI ↔ GUI

La web es solo frontend del motor CLI. Debe reflejar el mismo orden:

| GUI | CLI real |
|---|---|
| `Scan` | `set hosts` + `start_unauth` |
| `Authenticate` | `creds add` + `creds verify` + `start_auth` |
| `Enum Users` | `enum users` |
| `AS-REP Roast` | `asreproast` |
| `Kerberoast` | `kerberoast` |
| `Spray` | `spray <password>` |
| `ACLs` | `acls` |
| `ADCS` | `adcs` |
| `Coerce` | `coerce` |
| `Exploit` | `exploit` |
| `Pivot` | `pivot <user>` |
| `WinRM` | `winrm <account>` |
| `Brief` | `brief` |

### Criterio de coherencia

Para considerar que CLI y GUI están alineados, cada acción web debe:

- invocar el mismo comando del CLI;
- persistir el mismo workspace;
- producir los mismos artefactos (`users.json`, `credentials.json`, `graph.json`, `paths.json`, `findings.json`);
- reflejar el mismo progreso visual sin re-implementar la técnica en la web.

---

## 2. Decisión de lenguaje

### Recomendación: **Python 3.11+** (orquestador principal)

| Criterio | Python | Go | Rust | Ruby |
|---|---|---|---|---|
| Ecosistema AD existente | ★★★★★ Impacket, NetExec, Certipy, BloodHound, ldap3, kerberos libs | ★★☆☆☆ pocas libs maduras | ★★☆☆☆ reimplementar protocolos | ★☆☆☆☆ casi nulo |
| Velocidad de desarrollo | ★★★★★ | ★★★☆☆ | ★★☆☆☆ | ★★★★☆ |
| Integrar herramientas externas | ★★★★★ subprocess nativo | ★★★★☆ | ★★★☆☆ | ★★★☆☆ |
| CLI interactivo (REPL) | ★★★★★ cmd/prompt_toolkit | ★★★☆☆ cobra sin REPL rico | ★★☆☆☆ | ★★★★☆ |
| Distribución single-binary | ★★☆☆☆ (PyInstaller/Nuitka) | ★★★★★ | ★★★★★ | ★★☆☆☆ |
| Performance red masiva | ★★★☆☆ | ★★★★★ | ★★★★★ | ★★★☆☆ |
| Parsing LDAP/Kerberos/SMB | ★★★★★ libs battle-tested | ★★★☆☆ | ★★★★☆ (con esfuerzo) | ★★☆☆☆ |
| Curva para pentesters | ★★★★★ ya lo usan todos | ★★★☆☆ | ★★☆☆☆ | ★★☆☆☆ |

### Por qué Python y no otro

**ADScan ya demostró el modelo:** Python orquesta Docker + Impacket + NetExec + badldap + kerbad + aiosmb. El 90% del valor no está en reinventar Kerberos, sino en **encadenar** técnicas con estado (workspaces, credenciales, grafo).

- **Go** sería ideal para un escáner de red o un binario portable, pero obligaría a reimplementar o envolver en CGo gran parte del stack AD. Tiempo de desarrollo 3–5× mayor para paridad funcional.
- **Rust** aporta seguridad y rendimiento, pero el ecosistema AD ofensivo es inmaduro. Tiene sentido solo para módulos críticos de performance (fase futura).
- **Ruby** no tiene masa crítica en AD pentesting.

### Arquitectura híbrida futura (opcional, fase 3+)

```
┌─────────────────────────────────────────┐
│  Python — CLI, orquestación, grafo, UX  │
├─────────────────────────────────────────┤
│  Wrappers — Impacket, NetExec, Certipy  │
├─────────────────────────────────────────┤
│  Go/Rust (futuro) — port scan masivo,   │
│  hash cracking distribuido, collectors  │
└─────────────────────────────────────────┘
```

### Stack técnico elegido

| Capa | Tecnología |
|---|---|
| Lenguaje | Python ≥ 3.11 |
| CLI / REPL | `typer` + `prompt_toolkit` (autocomplete, historial) |
| Output | `rich` (tablas, paneles, progreso) |
| LDAP | `ldap3` (sync) → migrar a async si hace falta |
| Kerberos | `impacket` / `kerbad` |
| SMB | `impacket` + `smbprotocol` / subprocess NetExec |
| DNS | `dnspython` |
| Grafo | JSON propio + export BloodHound CE |
| Estado | JSON por workspace (como ADScan) |
| Tests | `pytest` |
| Lint | `ruff` |
| Empaquetado | `uv` / `pipx` |

### Compatibilidad — modelo Python (no binario nativo)

ADMapper se distribuye como **paquete pip** con entry point `admapper`. Requiere Python 3.11+; no es un ejecutable único tipo PyInstaller (eso sería fase posterior).

**Tres capas** — ver análisis completo en **`docs/COMPATIBILITY.md`**:

| Capa | Instalación | Capacidades |
|---|---|---|
| **CORE** | `pip install admapper` | CLI, DNS, ports, LDAP enum/spray/verify, workspaces JSON |
| **RECON** | `pip install admapper[recon]` | Impacket: SAMR, RID, SMB, AS-REP, Kerberoast, verify SMB/KRB |
| **EXTERNAL** | Usuario (brew/apt/PATH) | hashcat, john, kerbrute, nxc — **no incluidos en el paquete** |

Garantía multiplataforma real: **todo lo CORE + RECON** usa Python/`sys.executable` — mismo código en macOS, Linux y Windows. Lo EXTERNAL depende de binarios del SO.

| Plataforma | Prioridad | Instalación típica |
|---|---|---|
| **macOS** | ★★★★★ | venv + `pip install -e ".[recon]"` — entorno de desarrollo |
| **Linux** | ★★★★★ | Kali/Debian + pip; wordlists en `/usr/share/wordlists` |
| **Windows** | ★★★★☆ | venv activo; Impacket en `Scripts\`; LDAP spray sin extras |

**Módulos:** `admapper/core/platform.py` (PATH, subprocess), `admapper/core/compatibility.py` (matriz por comando).

**Diagnóstico:** comando `platform` en el shell.

Guías: **`docs/COMPATIBILITY.md`** (análisis) · **`docs/PLATFORMS.md`** (instalación por SO)

---

## 3. Arquitectura del proyecto

### Estructura de directorios

```
admapper/
├── admapper/                      # Paquete principal
│   ├── core/                  # Session, workspace, paths, credentials store, output
│   ├── models/                # Dataclasses (Credential, UserRecord, …)
│   ├── methodology/           # Canonical engagement phases (P1–P12)
│   ├── analysis/              # Operator intel: readiness, vectors, user_match, password rules
│   ├── cli/                   # Typer entrypoints and shell dispatch
│   ├── recon/                 # Unauthenticated discovery
│   ├── enumeration/           # User enumeration (SAMR, LDAP)
│   ├── creds/                 # Roast, spray, verify, Kerberos skew
│   ├── auth/                  # Authenticated LDAP/SMB enum, BloodHound export
│   ├── graph/                 # Attack graph + dashboard UI (ops_payload, ops_html, dashboard_server)
│   ├── exploit/               # Automated exploit chain
│   ├── escalate/              # Pivot and next-hop edges
│   ├── engage/                # Auto-engagement & task execution orchestration
│   ├── chain/                 # Automated exploit chain analysis
│   ├── guides/                # Manual technique catalog and pentest book
│   ├── report/                # Engagement map, export, MITRE Navigator
│   └── <technique>/           # Módulos específicos: acl, adcs, kerberos, coerce, cves, mssql, postex, wsus, winrm
├── workspaces/                # engagement data (gitignored)
├── tests/                     # unit and integration tests
├── docs/                      # documentation
├── pyproject.toml
└── README.md
```

Cada paquete de técnica específica (`<technique>/`) provee típicamente:
- `analyze.py`: Análisis de hallazgos del workspace basados en artefactos JSON.
- `catalog.py`: Metadatos de la técnica e identificadores de MITRE ATT&CK.
- `render.py`: Funciones de renderizado para salida en consola (CLI).

### Flujo de datos

1. **Workspace** (`~/.admapper/workspaces/<name>/` por defecto) contiene únicamente artefactos JSON del engagement activo. Estos datos nunca deben subirse al control de versiones.
2. Los comandos **Scan/Run** escriben estados serializados como `unauth_scan.json`, `credentials.json`, `auth_inventory.json`, etc.
3. El motor de **Análisis** consume estos artefactos para construir el payload operativo (`ops_payload`), vectores de ataque y la inteligencia general del engagement.
4. El comando **Dashboard** (`admapper dashboard` / `admapper g`) expone el servidor local HTTP para la interfaz interactiva web y permite gatillar subprocesses del CLI en tiempo real.

### Fases del Pentest

Mapeadas en un modelo canónico centralizado en `admapper/methodology/unified.py` (Fases P1 a P12). La barra interactiva del frontend expone 9 pasos consolidados mapeados directamente a estas fases.

### Seguridad y Secretos

- Las credenciales y hashes se almacenan en texto plano por diseño en `credentials.json` bajo el workspace del operador (máquina local).
- Todos los reportes o elementos HTML dinámicos generados (`ad_ops.html`, `attack_graph.html`) deben almacenarse exclusivamente dentro del directorio del workspace para evitar fugas.
- El servidor de dashboard enmascara los secretos en las transmisiones JSON y en los outputs de la consola. No se deben embeber credenciales crudas en payloads transmitidos al front.

### Principios de diseño

1. **Un módulo = una técnica** con interfaz uniforme: `discover() → execute() → export()`.
2. **Estado explícito** — cada módulo lee/escribe artefactos JSON en el workspace.
3. **Confirmación antes de acción ruidosa** — spray, roast masivo, DCSync, etc.
4. **Sin Docker obligatorio** — dependencias pip; Docker opcional para labs.
5. **Tests con mocks** — no requiere dominio AD real para CI.
6. **Guía de explotación manual en cada técnica** — como BloodHound “Abuse”:
   catálogo en `admapper/guides/catalog.py`, render tras cada hallazgo,
   comando `guide <technique>` para consultar en cualquier momento.
   Cada entrada incluye: prerequisitos, pasos manuales, comandos copy-paste,
   herramientas, MITRE ID y siguientes pasos en ADMapper.

### Workspace (artefactos por dominio)

```
workspaces/<engagement>/<domain>/
├── config.json              # DCs, realm, opciones
├── hosts.json               # inventario de hosts
├── users.json               # inventario unificado de usuarios
├── credentials.json         # creds verificadas (user/hash/ticket)
├── findings.json            # hallazgos con severidad + MITRE
├── kerberoast_hashes.json
├── asreproast_hashes.json
├── spray_history.json
├── graph.json               # grafo de ataque nativo
└── bloodhound/              # export compatible BH CE
```

---

## 4. Roadmap — LO QUE HACEMOS AHORA

Las fases están ordenadas por **dependencia**: cada una consume la salida de las anteriores y habilita las siguientes.

---

### Fase 0 — Fundación del proyecto

> Sin esto, nada más funciona. Primera prioridad absoluta.

| ID | Tarea | Entregable | Estado |
|---|---|---|---|
| 0.1 | Inicializar `pyproject.toml`, estructura de paquetes, `uv`/`pip` | Repo compilable | ✅ |
| 0.2 | CLI base: `admapper start` abre shell interactivo | REPL con prompt | ✅ |
| 0.3 | Sistema de workspaces: `set workspace <name>`, `set domain <fqdn>` | Persistencia JSON | ✅ |
| 0.4 | Módulo de output (`rich`): tablas, banners, confirmaciones rojo/amarillo/verde | UX consistente | ✅ |
| 0.5 | Store de credenciales: add/list/verify estructura | `credentials.json` | ✅ |
| 0.6 | Config global: `~/.admapper/config.json` | Preferencias operador | ✅ |
| 0.7 | Modos de operación: `auto` / `semi` / `manual` | Flag en workspace | ✅ |
| 0.8 | Tests base + CI (ruff, pytest) | Pipeline mínimo | ✅ |

**Criterio de done:** `admapper start` → crear workspace → guardar config → salir → reabrir y recuperar estado.

---

### Fase 1 — Reconocimiento sin credenciales (DNS + servicios)

> Primera técnica real. Descubre el dominio y los DCs.

| ID | Tarea | Técnica ADScan equivalente | MITRE | Estado |
|---|---|---|---|---|
| 1.1 | Resolución DNS: SRV `_ldap._tcp`, `_kerberos._tcp`, `_gc._tcp` | DNS enumeration | T1018 | ✅ |
| 1.2 | Inferencia de dominio desde IP/rango (`set hosts`) | Domain discovery | T1018 | ✅ |
| 1.3 | Probe LDAP: bind anónimo, RootDSE, naming contexts | LDAP anonymous | T1087.002 | ✅ |
| 1.4 | Probe SMB: null session, guest, signing requerido | SMB null session | T1021.002 | ✅ |
| 1.5 | Probe Kerberos: realm, KDC reachable | Kerberos enum | T1558 | ✅ |
| 1.6 | Service discovery en rango (puertos 88, 389, 445, 5985, 1433) | Port scan | T1046 | ✅ |
| 1.7 | Comando: `start_unauth` orquesta 1.1–1.6 | Workflow unauth | — | ✅ |
| 1.8 | Exportar hallazgos a `findings.json` | Evidence export | — | ✅ |

**Depende de:** Fase 0  
**Habilita:** Fase 2, 3  
**Criterio de done:** Con solo un rango IP, descubrir FQDN del dominio, lista de DCs, y si LDAP anon / SMB null están abiertos.

---

### Fase 2 — Enumeración de usuarios (SAMR + LDAP + RID)

> Necesitamos usernames antes de roast o spray.

| ID | Tarea | Técnica ADScan equivalente | MITRE | Estado |
|---|---|---|---|---|
| 2.1 | SAMR `SamrEnumerateUsersInDomain` vía SMB null session | SAMR enumeration | T1087.002 | ✅ |
| 2.2 | LDAP anonymous: filtro `(objectClass=user)` si bind anon funciona | LDAP user enum | T1087.002 | ✅ |
| 2.3 | RID cycling (LSARPC) como fallback cuando SAMR falla | RID cycling | T1087.002 | ✅ |
| 2.4 | Merge de fuentes → `users.json` unificado con `sources[]` | Unified inventory | — | ✅ |
| 2.5 | Extraer descripciones SAMR/LDAP (keywords sensibles) | User descriptions | T1087.002 | ✅ |
| 2.6 | Filtrar cuentas de máquina (`$`) vs humanas | User classification | — | ✅ |

**Depende de:** Fase 1 (DC + SMB/LDAP accesible)  
**Habilita:** Fases 3, 4, 5  
**Criterio de done:** Lista de ≥1 usuario real del dominio sin credenciales, con fuente de descubrimiento trazable.

---

### Fase 3 — Detección de cuentas roastables

> Identificar objetivos antes de solicitar tickets (bajo ruido).

| ID | Tarea | Técnica ADScan equivalente | MITRE | Estado |
|---|---|---|---|---|
| 3.1 | Detectar `DONT_REQ_PREAUTH` (UAC 0x400000) vía LDAP | AS-REP target ID | T1558.004 | ✅ |
| 3.2 | Detectar cuentas con SPN (excluir krbtgt, cuentas de máquina opcional) | Kerberoast target ID | T1558.003 | ✅ |
| 3.3 | Marcar usuarios en `users.json` con flags `asrep_roastable`, `kerberoastable` | Metadata en inventario | — | ✅ |
| 3.4 | Detectar `UF_DONT_REQUIRE_PREAUTH` sin LDAP (UserAccountControl vía SAMR) | Fallback SAMR | T1558.004 | ✅ |

**Depende de:** Fase 2  
**Habilita:** Fases 4, 5  
**Criterio de done:** Reporte de cuentas roastables sin haber solicitado ningún ticket aún.

> **Implementado:** `admapper/enumeration/roastable.py` — `detect_roastable_targets()` se ejecuta automáticamente al final de `enum users`. Emite `roastable_targets.json` + findings. Tests: `tests/test_roastable.py` (11 casos).

---

### Fase 4 — AS-REP Roasting

> Primera técnica de obtención de credenciales offline.

| ID | Tarea | Técnica ADScan equivalente | MITRE | Estado |
|---|---|---|---|---|
| 4.1 | Solicitar AS-REP para cuentas `DONT_REQ_PREAUTH` | AS-REP roast | T1558.004 | ✅ |
| 4.2 | Exportar hashes en formato hashcat (`$krb5asrep$23$...`) | Hash export | — | ✅ |
| 4.3 | Integración cracking opcional (hashcat/john/wordlist) | Hash cracking | T1110.002 | ✅ |
| 4.4 | Si crack exitoso → añadir a `credentials.json` | Credential capture | T1078 | ✅ |
| 4.5 | Comando: `asreproast [user ...]` | CLI directo | — | ✅ |

**Depende de:** Fases 2, 3  
**Habilita:** Fase 6 (auth), Fase 8  
**Criterio de done:** Hash AS-REP exportado; si hay wordlist, credencial recuperada automáticamente.

---

### Fase 5 — Kerberoasting

> Segunda técnica de credenciales offline; complementa AS-REP.

| ID | Tarea | Técnica ADScan equivalente | MITRE | Estado |
|---|---|---|---|---|
| 5.1 | Solicitar TGS para cuentas con SPN (sin creds si pre-auth no requerido, con creds si no) | Kerberoast | T1558.003 | ✅ |
| 5.2 | Exportar hashes (`$krb5tgs$23$...`) | Hash export | — | ✅ |
| 5.3 | Cracking opcional con wordlist | Hash cracking | T1110.002 | ✅ |
| 5.4 | Credencial recuperada → `credentials.json` | Credential capture | T1078 | ✅ |
| 5.5 | Comando: `kerberoast [user ...]` | CLI directo | — | ✅ |

**Depende de:** Fases 2, 3 (4 opcional si se necesita cred para preauth)  
**Habilita:** Fase 6, 8  
**Criterio de done:** Hash TGS exportado para ≥1 cuenta con SPN.

---

### Fase 6 — Password Spraying

> Primer ataque online; necesita usuarios + política de lockout.

| ID | Tarea | Técnica ADScan equivalente | MITRE | Estado |
|---|---|---|---|---|
| 6.1 | Fetch política de contraseñas del dominio (lockoutThreshold, lockoutDuration) vía LDAP | Policy enum | T1110.003 | ✅ |
| 6.2 | Fetch `badPwdCount` por usuario (elegibilidad) | Lockout-aware | T1110.003 | ✅ |
| 6.3 | Motor de spray: 1 password × N users (NetExec/kerbrute) | Password spray | T1110.003 | ✅ |
| 6.4 | Variation spray (Season+Year!, Company123, etc.) | Variation spray | T1110.003 | ✅ |
| 6.5 | Historial `spray_history.json` (no repetir passwords) | Spray tracking | — | ✅ |
| 6.6 | Credenciales válidas → `credentials.json` | Credential capture | T1078 | ✅ |
| 6.7 | Comando: `spray <password>` con confirmación | CLI directo | — | ✅ |

**Depende de:** Fase 2  
**Habilita:** Fase 7, 8  
**Criterio de done:** Spray de 1 password contra lista de usuarios sin lockout, con credencial válida capturada si existe.

---

### Fase 7 — Verificación y gestión de credenciales

> Puente entre credenciales obtenidas y enumeración autenticada.

| ID | Tarea | Técnica ADScan equivalente | MITRE | Estado |
|---|---|---|---|---|
| 7.1 | Verificar credencial: LDAP bind (user+pass) | Auth verify | T1078 | ✅ |
| 7.2 | Verificar credencial: SMB auth (user+pass / hash) | Auth verify | T1078 | ✅ |
| 7.3 | Verificar credencial: Kerberos TGT (user+pass / hash) | Auth verify | T1078 | ✅ |
| 7.4 | Comando: `creds add <user> <secret>`, `creds list`, `creds verify` | Credential Mgmt | — | ✅ |
| 7.5 | Comando: `start_auth` — inicia flujo autenticado con creds del workspace | Auth workflow | — | ✅ |
| 7.6 | Marcar usuarios como `owned` en el grafo | Compromise tracking | — | ✅ |

**Depende de:** Fases 4, 5 o 6 (al menos una credencial)  
**Habilita:** Fase 8+  
**Criterio de done:** Añadir credencial manualmente, verificarla, y marcar usuario como comprometido.

---

### Fase 8 — Enumeración autenticada (LDAP + SMB)

> Con credenciales, el panorama cambia completamente.

| ID | Tarea | Técnica ADScan equivalente | MITRE | Estado |
|---|---|---|---|---|
| 8.1 | LDAP autenticado: usuarios, grupos, computadoras, GPOs, OUs | LDAP enum | T1087.002 | ✅ |
| 8.2 | LDAP: delegaciones (unconstrained, constrained, RBCD) | Delegation enum | T1558 | ✅ |
| 8.3 | LDAP: ACLs y ACEs sobre objetos de alto valor | ACL enum | T1098 | ✅ |
| 8.4 | SMB: sesiones activas, shares, permisos | SMB enum | T1021.002 | ✅ |
| 8.5 | SMB: GPP cpassword en SYSVOL | GPP passwords | T1552.006 | ✅ |
| 8.6 | Trust enumeration (dominios externos) | Trust spidering | T1482 | ✅ |
| 8.7 | ADCS: detectar CA + enumerar certificate templates | ADCS discovery | T1649 | ✅ |
| 8.8 | Postura: LAPS, SMB signing, NTLMv1, LDAP signing, DA sessions | Misconfig checks | varios | ✅ |
| 8.9 | Export BloodHound CE compatible JSON | BH collection | — | ✅ |

**Depende de:** Fase 7  
**Habilita:** Fases 9–16  
**Criterio de done:** `start_auth` produce inventario completo + `graph.json` + export BloodHound.

> **Implementado 8.8:** `admapper/auth/posture.py` — `check_security_posture()` se ejecuta automáticamente en `run_auth_enumeration()`. Emite `security_posture.json` + findings. Checks: SMB signing, LAPS, NTLMv1, LDAP signing, DA sessions.

---

### Fase 9 — Grafo de ataque y rutas

> El diferenciador de ADScan: de datos a caminos explotables.

| ID | Tarea | Técnica ADScan equivalente | MITRE | Estado |
|---|---|---|---|---|
| 9.1 | Modelo de grafo: nodos (user, group, computer, domain) + edges (ACL, memberOf, AdminTo, etc.) | Attack graph | — | ✅ |
| 9.2 | Catálogo de relaciones con metadata (MITRE, severidad, soporte) | Attack step catalog | — | ✅ |
| 9.3 | Algoritmo: rutas desde `owned` → Domain Admins (BFS/DFS con profundidad) | Path computation | — | ✅ |
| 9.4 | Comando: `paths` — listar rutas ordenadas por longitud/impacto | Path listing | — | ✅ |
| 9.5 | Comando: `paths show <id>` — detalle paso a paso con narrativa | Path detail | — | ✅ |
| 9.6 | Quick wins: User=Password, BlankPassword, GPP, creds en shares | Quick credential wins | T1078 | ✅ |

**Depende de:** Fase 8  
**Habilita:** Fases 10–16  
**Criterio de done:** Al menos 1 ruta calculada desde usuario owned hasta grupo de alto valor.

---

### Fase 10 — Abuso de ACLs

| ID | Tarea | Técnica | MITRE | Estado |
|---|---|---|---|---|
| 10.1 | GenericAll → modificar atributos / reset password | ACL abuse | T1098 | ✅ |
| 10.2 | GenericWrite → Shadow Credentials / SPN | ACL abuse | T1098 | ✅ |
| 10.3 | WriteDACL → auto-conceder GenericAll | ACL abuse | T1098 | ✅ |
| 10.4 | WriteOwner → tomar ownership → GenericAll | ACL abuse | T1098 | ✅ |
| 10.5 | ForceChangePassword | ACL abuse | T1098 | ✅ |
| 10.6 | AddMember → añadirse a grupo privilegiado | ACL abuse | T1098 | ✅ |
| 10.7 | AddSelf → GenericAll vía grupo | ACL abuse | T1098 | ✅ |
| 10.8 | ReadLAPSPassword / ReadGMSAPassword | ACL abuse | T1555 | ✅ |
| 10.9 | WriteSPN / SPNJack | SPNJack | T1558 | ✅ |
| 10.10 | DCSync (GetChanges / GetChangesAll) | DCSync | T1003.006 | ✅ |

**Depende de:** Fases 8, 9

---

### Fase 11 — Kerberos avanzado

| ID | Tarea | Técnica | MITRE | Estado |
|---|---|---|---|---|
| 11.1 | Timeroasting | Timeroast | T1558.003 | ✅ |
| 11.2 | Unconstrained delegation + coercion | Delegation abuse | T1558 | ✅ |
| 11.3 | Constrained delegation (AllowedToDelegate) | Delegation abuse | T1558 | ✅ |
| 11.4 | RBCD (AllowedToAct / AddAllowedToAct) | RBCD | T1134.001 | ✅ |
| 11.5 | Shadow Credentials (AddKeyCredentialLink) | Shadow Creds | T1098 | ✅ |
| 11.6 | Backup Operators escalation | BO abuse | T1098 | ✅ |

**Depende de:** Fases 8, 9

---

### Fase 12 — ADCS (current ESC catalog)

| ID | Tarea | Técnica | MITRE | Estado |
|---|---|---|---|---|
| 12.1 | Detección de templates vulnerables (current ESC catalog) | ADCS enum | T1649 | ✅ |
| 12.2 | Explotación ESC1 (SAN editable + EKU) | ESC1 | T1649 | ✅ |
| 12.3 | Explotación ESC8 (NTLM relay → web enrollment) | ESC8 | T1649 | ✅ |
| 12.4 | ESC2–ESC7, ESC9–ESC15 + Golden Certificate (una a una) | ADCS ESC | T1649 | ✅ |
| 12.5 | GoldenCert | CA abuse | T1649 | ✅ |

**Depende de:** Fase 8

---

### Fase 13 — Coerción y relay

| ID | Tarea | Técnica | MITRE | Estado |
|---|---|---|---|---|
| 13.1 | PetitPotam (EFSR RPC) | Coercion | T1187 | ✅ |
| 13.2 | PrinterBug (MS-RPRN) | Coercion | T1187 | ✅ |
| 13.3 | DFSCoerce, MS-EVEN, ShadowCoerce | Coercion | T1187 | ✅ |
| 13.4 | NTLM relay → LDAP (RBCD / Shadow Creds) | Relay | T1557.001 | ✅ |
| 13.5 | NTLM relay → ADCS (ESC8/ESC11) | Relay | T1649 | ✅ |
| 13.6 | NTLMv1 relay → RBCD / Shadow Creds | Relay | T1557.001 | ✅ |

**Depende de:** Fases 8, 12

---

### Fase 14 — Post-explotación local

| ID | Tarea | Técnica | MITRE | Estado |
|---|---|---|---|---|
| 14.1 | AdminTo → acceso SMB/WinRM | Lateral movement | T1021 | ✅ |
| 14.2 | SAM dump (registry) | Cred dump | T1003.002 | ✅ |
| 14.3 | LSA Secrets | Cred dump | T1003.004 | ✅ |
| 14.4 | LSASS dump | Cred dump | T1003.001 | ✅ |
| 14.5 | DCSync (DRSUAPI) | DCSync | T1003.006 | ✅ |
| 14.6 | DPAPI secrets | Cred dump | T1555 | ✅ |
| 14.7 | Credenciales en filesystem / shares | Share loot | T1552.001 | ✅ |
| 14.8 | RDP saved creds | Cred access | T1555.004 | ✅ |

**Depende de:** Fases 9, 10

---

### Fase 15 — MSSQL y movimiento lateral

| ID | Tarea | Técnica | MITRE | Estado |
|---|---|---|---|---|
| 15.1 | SQL Access / SQL Admin detection | MSSQL enum | T1021 | ✅ |
| 15.2 | Impersonation (SeImpersonate) | MSSQL privesc | T1068 | ✅ |
| 15.3 | Linked server lateral movement | MSSQL lateral | T1021 | ✅ |
| 15.4 | Trustworthy database escalation | MSSQL privesc | T1068 | ✅ |
| 15.5 | xp_cmdshell execution | MSSQL exec | T1059 | ✅ |

**Depende de:** Fase 8

---

### Fase 16 — CVEs y exploits

| ID | Tarea | Técnica | MITRE | Estado |
|---|---|---|---|---|
| 16.1 | noPac (CVE-2021-42278/42287) — detección + exploit confirmado | noPac | T1068 | ✅ |
| 16.2 | ZeroLogon (CVE-2020-1472) — detección, exploit con confirmación explícita | ZeroLogon | T1210 | ✅ |
| 16.3 | PrintNightmare — detección | PrintNightmare | T1068 | ✅ |
| 16.4 | MS17-010 (EternalBlue) — detección | EternalBlue | T1210 | ✅ |
| 16.5 | Catálogo CVE en DCs y workstations | CVE enum | T1210 | ✅ |

**Depende de:** Fase 8

---

### Fase 17 — Reporting y export

| ID | Tarea | Técnica ADScan equivalente | Estado |
|---|---|---|---|
| 17.1 | Export TXT/JSON de hallazgos | Evidence export | ✅ |
| 17.2 | MITRE ATT&CK Navigator layer | mitre-navigator | ✅ |
| 17.3 | Technical report JSON machine-readable | technical_report.json | ✅ |
| 17.4 | Executive PDF (futuro, no bloqueante) | PRO deliverable | ⬜ |

**Depende de:** Todas las fases anteriores

---

## 5. Orden de implementación (resumen ejecutivo)

```
Fase 0  ─── Fundación (CLI, workspace, creds store)
   │
Fase 1  ─── DNS + LDAP anon + SMB null + service discovery
   │
Fase 2  ─── SAMR + LDAP users + RID cycling → users.json
   │
Fase 3  ─── Detectar roastables (AS-REP + Kerberoast targets)
   │
   ├─ Fase 4 ─── AS-REP Roasting
   ├─ Fase 5 ─── Kerberoasting
   └─ Fase 6 ─── Password Spraying
         │
Fase 7  ─── Verificar creds + start_auth
   │
Fase 8  ─── Enumeración autenticada + GPP + trusts + ADCS discovery
   │
Fase 9  ─── Grafo de ataque + rutas
   │
   ├─ Fase 10 ── ACL abuse
   ├─ Fase 11 ── Kerberos avanzado
   ├─ Fase 12 ── ADCS ESC
   ├─ Fase 13 ── Coerción + relay
   ├─ Fase 14 ── Post-exploit local
   ├─ Fase 15 ── MSSQL
   └─ Fase 16 ── CVEs
         │
Fase 17 ─── Reporting
```

**Empezamos por Fase 0, luego Fase 1, y avanzamos secuencialmente.**  
No saltar fases: cada una valida la anterior con tests y, si es posible, un lab AD (HTB Forest es el benchmark de ADScan).

---

## 6. Checklist inmediata (próximas 2 semanas)

- [x] **0.1** Crear `pyproject.toml` y estructura de paquetes
- [x] **0.2** CLI `admapper start` con shell interactivo
- [x] **0.3** Workspaces con persistencia JSON
- [x] **0.4** Output con `rich` (banners, tablas, confirmaciones)
- [x] **1.1** Módulo DNS SRV discovery
- [x] **1.3** Probe LDAP anonymous
- [x] **1.4** Probe SMB null session
- [x] **1.7** Comando `start_unauth` integrado
- [ ] **2.1** SAMR user enumeration
- [ ] **2.4** Merge → `users.json`
- [ ] **3.1** Detectar AS-REP roastables
- [ ] **4.1** AS-REP Roasting funcional
- [ ] Tests unitarios para cada módulo con mocks

---

## 7. Criterios de calidad (cada técnica)

Toda técnica implementada debe cumplir:

1. **Módulo aislado** en su paquete (`recon/`, `creds/`, etc.).
2. **Tests unitarios** con mocks (sin AD real obligatorio).
3. **Artefacto JSON** en workspace (trazabilidad).
4. **Entrada en `findings.json`** con severidad + MITRE ID.
5. **Comando CLI directo** además del workflow automático.
6. **Confirmación** si la acción es ruidosa (spray, exploit, dump).
7. **Documentación inline** — docstring con requisitos previos y salida esperada.

---

## 8. LO QUE NO HACE ADScan (backlog futuro — después de paridad)

Estas capacidades las dejamos fuera del MVP pero las documentamos para no perder el hilo.

### 8.1 Técnicas que ADScan detecta pero no auto-exploita

| Técnica | Estado en ADScan | Nuestra oportunidad |
|---|---|---|
| PetitPotam / PrinterBug / DFSCoerce | Detecta, no auto-exploit | Auto-exploit con relay integrado desde v1 |
| Shadow Credentials directo | Parcial | Implementación nativa completa |
| GPP en grafo de ataque | Unsupported en catálogo | Integrar como edge ejecutable |
| AddKeyCredentialLink | Unsupported | Primera clase en Fase 11 |
| SID History / Golden Ticket | No cubierto | Fase futura |
| Silver Ticket | No cubierto | Fase futura |
| Pass-the-Ticket | Context only | Fase futura |
| GPO abuse (Scheduled Tasks) | No cubierto | Fase futura |
| AdminSDHolder abuse | No cubierto | Fase futura |
| DSRM credential sync | No cubierto | Fase futura |
| Trust key abuse (inter-domain) | Parcial (trust enum) | Explotación cross-domain |
| Child → Enterprise DA | Parcial | Cadena completa |

### 8.2 Fuera del scope AD on-prem de ADScan

| Área | Descripción | Prioridad futura |
|---|---|---|
| **Azure AD / Entra ID** | ROADToken, PRT, CA policies, Graph API | Alta |
| **ADFS** | Golden SAML, token abuse | Alta |
| **Azure AD Connect** | MSOL password sync abuse | Media |
| **Certificate-based auth (Smart Card)** | PKINIT abuse avanzado | Media |
| **AD CS en cloud (Intune PKI)** | ESC adaptado a cloud | Baja |
| **Defender / EDR evasion** | OPSEC, timing, noise budget | Media |
| **Continuous monitoring (CTEM)** | ADScan Enterprise | Baja (otro producto) |

### 8.3 Mejoras arquitectónicas sobre ADScan

| Mejora | Por qué |
|---|---|
| **Sin Docker obligatorio** | ADScan requiere Docker; nosotros pip install directo |
| **Licencia permisiva** | ADScan es BSL 1.1; nosotros Apache 2.0/MIT |
| **Código modular testeable** | ADScan es monolito de 9.x con `adscan_internal` enorme |
| **API programática** | SDK Python para CI/CD (`admapper ci`) sin REPL |
| **Plugins** | Terceros añaden técnicas sin fork |
| **OPSEC profiles** | Stealth / Normal / Lab presets |
| **Multi-tenant workspaces** | Varios dominios en un engagement |
| **Differential scans** | Solo re-escanear lo que cambió (delta) |

### 8.4 Labs de validación

| Lab | Qué valida | Fases |
|---|---|---|
| HTB Forest | AS-REP → SMB null → DCSync chain | 1–4, 8, 10, 14 |
| HTB Active | GPP → Kerberoast → ACL | 5, 8, 10 |
| HTB Cicada | ADCS ESC + trust | 8, 12, 13 |
| GOAD (Game of Active Directory) | Full chain | Todas |

---

## 9. Referencia: 64 técnicas ejecutables de ADScan

Para paridad, el catálogo de ADMapper final debe cubrir al menos estas relaciones del `attack_step_catalog` de ADScan:

<details>
<summary>Lista completa (click para expandir)</summary>

**Credenciales / roast / spray:**
`asreproasting`, `kerberoasting`, `timeroasting`, `passwordspray`, `useraspass`, `blankpassword`, `computerpre2k`

**ACL / LDAP:**
`genericall`, `genericwrite`, `owns`, `writedacl`, `writeowner`, `forcechangepassword`, `addself`, `addmember`, `readlapspassword`, `readgmsapassword`, `writeaccountrestrictions`, `writespn`, `spnjack`, `writelogonscript`, `dcsync`

**Delegación / Kerberos:**
`allowedtodelegate`, `hasshadowcredentials`, `ntlmv1relayrbcd`, `ntlmv1relayshadowcreds`

**ADCS:**
`adcsesc1`–`adcsesc15`, `coerceandrelayntlmtoadcs`, `goldencert`

**Lateral / acceso:**
`adminto`, `hassession`, `guestsession`, `canrdp`, `canpsremote`, `sqlaccess`, `sqladmin`

**MSSQL:**
`mssql_seimpersonate_escalation`, `mssql_token_theft_escalation`, `mssql_linked_server_lateral`, `mssql_impersonate_login`, `mssql_trustworthy_db_escalation`, `mssql_ntlmv2_theft`

**Post-exploit:**
`dumplsa`, `dumplsass`, `dumpdpapi`

**RODC / avanzado:**
`backupoperatorescalation`, `preparerodccredentialcaching`, `extractrodckrbtgtsecret`, `forgerodcgoldenticket`, `kerberoskeylist`

**Shares:**
`readshare`, `writeshare`, `fullcontrolshare`

</details>

---

## 10. Comandos CLI planificados

| Comando | Fase | Descripción |
|---|---|---|
| `admapper start` | 0 | Abre shell interactivo |
| `set workspace <name>` | 0 | Selecciona/crea workspace |
| `set domain <fqdn>` | 0 | Define dominio objetivo |
| `set hosts <cidr/ip>` | 1 | Define rango objetivo |
| `start_unauth` | 1 | Recon sin credenciales |
| `enum users` | 2 | Enumerar usuarios (SAMR/LDAP/RID) |
| `asreproast` | 4 | AS-REP roasting + cracking opcional |
| `guide <technique>` | * | Explotación manual (estilo BloodHound) |
| `start_auth` | 7 | Flujo autenticado completo |
| `enum users` | 2 | Enumerar usuarios |
| `asreproast` | 4 | AS-REP roasting |
| `kerberoast` | 5 | Kerberoasting |
| `spray <password>` | 6 | Password spraying |
| `creds add/list/verify` | 7 | Gestión de credenciales |
| `paths` | 9 | Listar rutas de ataque |
| `exploit <step>` | 10+ | Ejecutar paso de ruta |
| `export json/txt` | 17 | Exportar hallazgos |

---

## 11. Notas de sesión

> Espacio para anotar decisiones tomadas durante el desarrollo.

| Fecha | Decisión |
|---|---|
| 2026-06-04 | Lenguaje: Python 3.11+. Nombre proyecto: **ADMapper**. Licencia: Apache 2.0. |
| 2026-06-04 | Renombrado de ADIR → **ADMapper** (CLI: `admapper`, config: `~/.admapper/`). |
| 2026-06-04 | Orden: Fase 0 → 1 → 2 → 3 → 4/5/6 → 7 → 8+. Sin saltos. |
| 2026-06-04 | Benchmark de paridad: ADScan LITE v9.x, 64 técnicas ejecutables. |
| 2026-06-24 | Fase 3 completada: `roastable.py` — detección pre-ticket de targets AS-REP + Kerberoast + PASSWD_NOTREQD. |
| 2026-06-24 | Fase 8.8 completada: `posture.py` — LAPS, SMB signing, NTLMv1, LDAP signing, DA sessions checks. |
| 2026-06-24 | Backlog — `coerce/exploit.py`: motor auto-exploit ntlmrelayx + coercedores (PetitPotam, PrinterBug, DFSCoerce). |
| 2026-06-24 | Backlog — `core/opsec.py`: OPSEC profiles STEALTH/NORMAL/LAB. CLI: `admapper opsec set <profile>`. Tests: `test_opsec.py`. |
| 2026-06-24 | Backlog — `exploit/tickets.py`: `inject_ticket()` + `pass_the_ticket()` — PTT cross-platform (KRB5CCNAME / Rubeus). |
| 2026-06-24 | Backlog — `exploit/persistence.py`: `exploit_dsrm_backdoor()` — dump DSRM hash + DsrmAdminLogonBehavior. |
| 2026-06-24 | Backlog — `exploit/trusts.py`: `exploit_sid_history_nopac()` — SID History via CVE-2021-42278/42287 (noPac). |
| 2026-06-25 | Auditorías de Postura PingCastle: Stale Systems, GPO Abuse, Stale AdminCount y ESC8 HTTP web enrollment. |
| 2026-06-25 | CLI Visual Style System (output.py), `--no-color` option, privilege-free LDAP anonymous DC clock sync, and robust subprocess worker error wrapping. |

---

*Este documento es la fuente de verdad del proyecto. Actualizar al completar cada fase.*
