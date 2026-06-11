from __future__ import annotations

from typing import TYPE_CHECKING

from admapper.core.output import print_error, print_warning
from admapper.models.credential import CredentialType
from admapper.models.workspace import OperationMode

if TYPE_CHECKING:
    from admapper.core.session import Session

_HELP_ESSENTIAL = """
Essential (90% del engagement):
  show                         Dashboard: fase, creds, siguiente acción
  analyst [--deep]             Escenario completo + top 3 acciones
  start_unauth                 Recon sin creds
  start_auth                   Enum LDAP/SMB + BloodHound
  exploit                      Loot shares → creds → ACLs
  escalate                     Siguiente hop desde pivot
  escalate exec                Ejecutar hop recomendado
  creds list|add|verify        Gestión de credenciales
  acls | acls show <id>        ACL abuse
  adcs | postex | wsus         Módulos avanzados (show <id> en cada uno)
  export                       Reportes JSON/TXT/HTML
  guide <technique>            Pasos manuales MITRE
  help all                     Lista completa de comandos
  exit | quit
"""

_HELP_ALL = """
All commands:
  set workspace|domain|hosts|mode <value>
  workspaces                   List workspaces
  creds remove <id>
  enum users | enum auth
  asreproast | kerberoast | spray <pass>
  graph | graph show        Attack graph (ASCII, sin BloodHound CE)
  paths | paths show <id>
  kerberos | timeroast | coerce | chain | mssql | cves
  postex scan|deploy|run|show
  wsus run|script | adcs run
  escalate pivot|mark|refresh|sanitize
  cves exploit zerologon|nopac
  doctor | platform | version | scan
"""


def require_workspace(session: Session) -> bool:
    if session.workspace is None:
        print_error("no active workspace — run: set workspace <name>")
        return False
    return True


def parse_set_mode(value: str) -> OperationMode | None:
    try:
        return OperationMode(value.strip().lower())
    except ValueError:
        print_error("mode must be one of: auto, semi, manual")
        return None


def parse_cred_type(value: str | None) -> CredentialType:
    if not value:
        return CredentialType.PASSWORD
    try:
        return CredentialType(value.strip().lower())
    except ValueError:
        print_warning(f"unknown cred type '{value}', using password")
        return CredentialType.PASSWORD
