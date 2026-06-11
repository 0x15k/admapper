"""Normalize admapper CLI output for the game terminal (learner-friendly)."""

from __future__ import annotations

import re
from dataclasses import dataclass, field

_ANSI_RE = re.compile(r"\x1b\[[0-9;]*m")
_RICH_TAG_RE = re.compile(r"\[[/]?[a-z]+(?: [a-z]+)?\]", re.IGNORECASE)

_SUPPRESS_PATTERNS: tuple[re.Pattern[str], ...] = tuple(
    re.compile(p)
    for p in (
        r"^✓ workspace active:",
        r"^✓ hosts set:",
        r"^✓ mode set:",
        r"^✓ domain set:",
        r"^→ unauth_scan\.json cached",
        r"^→ domain:",
        r"^→ syncing clock with DC",
        r"^! clock sync failed:",
        r"^→ continuing — Kerberos will auto-probe",
        r"^\[libfaketime\]",
        r"^→ usando clock skew Kerberos en caché",
        r"^→ \[admapper\] automático:",
        r"^→ automático:",
        r"^✓ graph updated",
        r"^✓ estado auth guardado",
        r"^✓ inventario guardado",
        r"^✓ grafo actualizado",
        r"^✓ export BloodHound",
        r"^→ reportes →",
        r"^✓ post-ex playbook saved",
        r"^✓ ADMapper — mapa de engagement",
        r"^→ grafo → file://",
        r"^✓  log exploit →",
        r"^✓  log exploit",
        r"^═+$",
        r"^  MAPA DE ENGAGEMENT",
        r"^  Dominio\s*:",
        r"^  DC\s*:",
        r"^  ESTÁS AQUÍ",
        r"^  ● owned",
        r"^  ● pivot",
        r"^  METODOLOGÍA",
        r"^  ENUM DESTACADA",
        r"^  CREDENCIALES DESCUBIERTAS",
        r"^  ┌",
        r"^  ├",
        r"^  └",
        r"^  │",
        r"^  ACCESO PIVOT",
        r"^  usuario\s+ldap",
        r"^  \* cadena del archivo",
        r"^  BLOQUEADO / DESPUÉS",
        r"^  SIGUIENTE PASO\s+\[listo\]",
        r"^  Técnica\s*:",
        r"^  Comando\s*:",
        r"^  ⚠ BLOQUEO",
        r"^┏",
        r"^┡",
        r"^┃",
        r"^┗",
        r"^└",
        r"^│",
        r"^Auth checks$",
        r"^Post-exploitation opportunities$",
        r"^Engagement$",
        r"^Domain controller$",
        r"^     Auth checks",
    )
)

_DEDUPE_WINDOW = 12


@dataclass
class GameTerminalFilter:
    """Stream filter: strip noise, dedupe, fold auth-verify retries."""

    _recent: list[str] = field(default_factory=list)
    _pending_invalid: list[str] = field(default_factory=list)
    _skew_warned: bool = False

    def reset(self) -> None:
        self._recent.clear()
        self._pending_invalid.clear()
        self._skew_warned = False

    def _clean(self, line: str) -> str:
        line = _ANSI_RE.sub("", line)
        line = _RICH_TAG_RE.sub("", line)
        return line.strip()

    def _is_dup(self, line: str) -> bool:
        if line in self._recent[-_DEDUPE_WINDOW :]:
            return True
        self._recent.append(line)
        if len(self._recent) > _DEDUPE_WINDOW * 2:
            self._recent = self._recent[-_DEDUPE_WINDOW:]
        return False

    def _should_suppress(self, line: str) -> bool:
        for pat in _SUPPRESS_PATTERNS:
            if pat.search(line):
                return True
        if "fix clock skew:" in line or "Protected Users need Kerberos" in line:
            if self._skew_warned:
                return True
            self._skew_warned = True
        return False

    def _fold_auth_block(self, line: str) -> str | None:
        if line.startswith("! credential invalid:"):
            user = line.split(":", 1)[-1].strip().split("(")[0].strip()
            self._pending_invalid.append(user)
            return None
        if line.startswith("✓ credential valid:"):
            user = line.split(":", 1)[-1].strip().split("(")[0].strip()
            if user in self._pending_invalid:
                self._pending_invalid.remove(user)
            return f"✓ Credencial válida: {user}"
        if line.startswith("→ Protected Users — only Kerberos"):
            return "→ Protected Users: solo Kerberos (NTLM bloqueado)"
        if line.startswith("! credential invalid:"):
            return None
        if line.startswith("! Protected Users — Kerberos required"):
            return None
        return line

    def process(self, raw: str) -> str | None:
        line = self._clean(raw)
        if not line or line.startswith("[exit"):
            return line or None

        folded = self._fold_auth_block(line)
        if folded is None:
            return None
        line = folded

        if self._should_suppress(line):
            return None
        if self._is_dup(line):
            return None

        # Compact path lines
        if line.startswith("→  exploit acl-"):
            return line.replace("→  ", "→ ")
        if line.startswith("→ Phase "):
            return line.replace("Phase 14", "Fase POST-EX").replace("Phase 18", "Fase EXPLOIT")

        return line
