from __future__ import annotations

from typing import TYPE_CHECKING

from admapper.core.output import print_error, print_warning
from admapper.models.credential import CredentialType
from admapper.models.workspace import OperationMode

if TYPE_CHECKING:
    from admapper.core.session import Session

_HELP_ESSENTIAL = """
Essential (90% of the engagement):
  show                         Dashboard: phase, creds, next action
  analyst [--deep]             Complete scenario + top 3 actions
  start_unauth                 Recon without credentials
  start_auth                   LDAP/SMB enumeration + BloodHound
  exploit                      Loot shares → creds → ACLs
  escalate                     Next hop from pivot
  escalate exec                Execute recommended hop
  creds list|add|verify        Credential management
  acls | acls show <id>        ACL abuse
  adcs | postex | wsus         Advanced modules (show <id> in each)
  export                       JSON/TXT/HTML reports
  guide <technique>            MITRE manual steps
  help all                     Complete list of commands
  exit | quit
"""

_HELP_ALL = """
All commands:
  set workspace|domain|hosts|mode <value>
  workspaces                   List workspaces
  creds remove <id>
  enum users | enum auth
  asreproast | kerberoast | spray <pass>
  graph | graph show        Attack graph (ASCII, without BloodHound CE)
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
