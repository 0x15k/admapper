from __future__ import annotations

import re
from dataclasses import dataclass

from admapper.postex.loot_intel import LootIntelResult

_WIN_PATH_RE = re.compile(r"([A-Z]:\\[^\s'\"<>|]+)", re.IGNORECASE)
_ZIP_NAME_RE = re.compile(r"([\w.-]+\.zip)", re.IGNORECASE)
_DLL_NAME_RE = re.compile(r"([\w.-]+\.dll)", re.IGNORECASE)
_RUN_AS_RE = re.compile(r"(?:[\w.-]+\\)([\w$.-]+)", re.IGNORECASE)
_TASK_NAME_RE = re.compile(r"Task \[([^\]]+)\]", re.IGNORECASE)
_MONITOR_LOCAL_ZIP_RE = re.compile(
    r"No updates found locally:\s*(.+?)\.\s*$",
    re.IGNORECASE,
)
_MONITOR_LOADER_RE = re.compile(
    r"Loading update applier:\s*(\S+)",
    re.IGNORECASE,
)
_MONITOR_CORE_ZIP_RE = re.compile(
    r"Core did not find file\s+(\S+\.zip)",
    re.IGNORECASE,
)
_DLL_HIJACK_LINE_RE = re.compile(
    r"\.dll|\.zip|scheduled.?task|hijack|load(?:ing)?\s+\w+\.dll|update check|monitor|no updates found locally",
    re.IGNORECASE,
)


def _intel_from_monitor_lines(lines: list[str]) -> tuple[str | None, str | None, str | None, str | None]:
    """Parse a generic monitor.log → zip, dll, drop_path, monitor_log_path."""
    zip_name = dll_name = drop_path = monitor_log_path = None
    for line in lines:
        local = _MONITOR_LOCAL_ZIP_RE.search(line)
        if local:
            full = local.group(1).strip()
            z, _ = _pick_zip_dll(full)
            if z:
                zip_name = zip_name or z
                drop_path = drop_path or _drop_path_from_zip_path(full, z)
        core = _MONITOR_CORE_ZIP_RE.search(line)
        if core:
            zip_name = zip_name or core.group(1)
        loader = _MONITOR_LOADER_RE.search(line)
        if loader:
            dll_path = loader.group(1).strip()
            d_match = _DLL_NAME_RE.search(dll_path)
            if d_match:
                dll_name = dll_name or d_match.group(1)
        for path_match in _WIN_PATH_RE.finditer(line):
            path = path_match.group(1).rstrip(".")
            if path.lower().endswith(".log"):
                monitor_log_path = monitor_log_path or path
    return zip_name, dll_name, drop_path, monitor_log_path


@dataclass(frozen=True)
class HijackIntel:
    payload_zip: str
    payload_dll: str
    drop_path: str
    monitor_log_path: str | None = None
    task_name_hint: str | None = None
    com_task_filter: str | None = None


def _pick_zip_dll(text: str) -> tuple[str | None, str | None]:
    zip_match = _ZIP_NAME_RE.search(text)
    dll_match = _DLL_NAME_RE.search(text)
    return (
        zip_match.group(1) if zip_match else None,
        dll_match.group(1) if dll_match else None,
    )


def _drop_path_from_zip_path(full_path: str, zip_name: str) -> str:
    lower = full_path.lower()
    zlower = zip_name.lower()
    if zlower in lower:
        idx = lower.rfind(zlower)
        return full_path[:idx].rstrip("\\/")
    parent = full_path.rsplit("\\", 1)[0]
    return parent or full_path


def _normalize_run_as(user: str) -> str:
    user = user.strip()
    if "\\" in user:
        user = user.split("\\", 1)[1]
    return user


def _score_com_task(
    *,
    zip_name: str | None,
    dll_name: str | None,
    run_as: str,
) -> int:
    score = 0
    if zip_name:
        score += 2
    if dll_name:
        score += 1
    if run_as and not run_as.endswith("$"):
        lowered = run_as.lower()
        if lowered not in {"system", "localservice", "networkservice"}:
            score += 3
    return score


def parse_task_xml_file_output(text: str) -> str:
    """Parse a scheduled-task XML file (type C:\\Windows\\System32\\Tasks\\...) to pipe format."""
    if "<Task" not in text and "<task" not in text.lower():
        return ""
    import xml.etree.ElementTree as ET

    try:
        root = ET.fromstring(text)
    except ET.ParseError:
        return ""

    ns = ""
    if root.tag.startswith("{"):
        ns = root.tag.split("}")[0] + "}"

    def _find(path: str) -> str:
        node = root.find(f"{ns}{path}")
        return (node.text or "").strip() if node is not None else ""

    user = _find("Principals/Principal/UserId") or _find("Principals/Principal/GroupId")
    exe = _find("Actions/Exec/Command")
    args = _find("Actions/Exec/Arguments")
    name = _find("RegistrationInfo/URI") or _find("RegistrationInfo/Author") or "scheduled_task"
    if "\\" in name:
        name = name.rsplit("\\", 1)[-1]
    if not exe and not args:
        return ""
    return f"{name}|{user}|{exe}|{args}"


def parse_schtasks_list_output(text: str) -> str:
    """Convert schtasks /query /fo LIST /v blocks to pipe-delimited task lines."""
    lines_out: list[str] = []
    current: dict[str, str] = {}

    def _flush() -> None:
        task_name = current.get("TaskName", "").strip()
        if not task_name:
            current.clear()
            return
        name = task_name.rsplit("\\", 1)[-1] if "\\" in task_name else task_name
        user = current.get("Run As User", "").strip()
        task_to_run = current.get("Task To Run", "").strip()
        exe = task_to_run
        args = ""
        if task_to_run:
            parts = task_to_run.split(None, 1)
            if parts and parts[0].lower().endswith((".exe", ".bat", ".cmd", ".com")):
                exe = parts[0]
                args = parts[1] if len(parts) > 1 else ""
        lines_out.append(f"{name}|{user}|{exe}|{args}")
        current.clear()

    for line in text.splitlines():
        stripped = line.strip()
        if not stripped:
            _flush()
            continue
        if ":" not in stripped:
            continue
        key, _, val = stripped.partition(":")
        key = key.strip()
        val = val.strip()
        if key in ("TaskName", "Run As User", "Task To Run", "Start In"):
            current[key] = val
    _flush()
    return "\n".join(lines_out)


def intel_from_com_tasks(com_task_output: str) -> HijackIntel | None:
    """Derive DLL-hijack intel from COM/schtasks pipe-delimited task lines."""
    best: tuple[int, str, str, str, str, str] | None = None

    for line in com_task_output.splitlines():
        line = line.strip()
        if not line or "|" not in line:
            continue
        parts = line.split("|", 3)
        while len(parts) < 4:
            parts.append("")
        name, user, exe, args = (p.strip() for p in parts)
        combined = f"{exe} {args}".strip()
        zip_name, dll_name = _pick_zip_dll(combined)
        if not zip_name and not dll_name:
            continue

        drop_path: str | None = None
        monitor_log_path: str | None = None
        for path_match in _WIN_PATH_RE.finditer(combined):
            path = path_match.group(1).rstrip(".")
            if zip_name and zip_name.lower() in path.lower():
                drop_path = _drop_path_from_zip_path(path, zip_name)
            elif path.lower().endswith(".log"):
                monitor_log_path = path
            elif dll_name and dll_name.lower() in path.lower() and "\\" in path:
                drop_path = path.rsplit("\\", 1)[0]

        run_as = _normalize_run_as(user)
        score = _score_com_task(zip_name=zip_name, dll_name=dll_name, run_as=run_as)
        candidate = (
            score,
            name,
            zip_name or "payload.zip",
            dll_name or "payload.dll",
            drop_path or r"C:\ProgramData",
            run_as,
        )
        if best is None or candidate[0] > best[0]:
            best = candidate

    if best is None:
        return None

    _, task_name, zip_name, dll_name, drop_path, run_as = best
    monitor_log_path = f"{drop_path.rstrip(chr(92))}\\Logs\\monitor.log"
    com_filter = task_name or (zip_name.split(".")[0] if zip_name else None)
    return HijackIntel(
        payload_zip=zip_name,
        payload_dll=dll_name,
        drop_path=drop_path,
        monitor_log_path=monitor_log_path,
        task_name_hint=task_name,
        com_task_filter=com_filter,
    )


def extract_hijack_intel(
    loot: LootIntelResult | None,
    *,
    monitor_log: str = "",
    com_task_output: str = "",
) -> HijackIntel | None:
    """Derive DLL-hijack paths from loot and remote monitor logs (domain-agnostic)."""
    corpus: list[str] = []
    task_hint: str | None = None

    if loot:
        corpus.extend(loot.zip_dll_refs)
        corpus.extend(loot.dll_hijack_refs)
        for hint in loot.task_hints:
            if hint.task_name:
                task_hint = task_hint or hint.task_name
            corpus.append(f"{hint.source_file}: {hint.line}")

    if monitor_log:
        corpus.extend(monitor_log.splitlines())
    if com_task_output:
        corpus.extend(com_task_output.splitlines())

    zip_name = dll_name = None
    drop_path = monitor_log_path = None

    if monitor_log:
        mz, md, mdrop, mlog = _intel_from_monitor_lines(monitor_log.splitlines())
        zip_name = zip_name or mz
        dll_name = dll_name or md
        drop_path = drop_path or mdrop
        monitor_log_path = monitor_log_path or mlog

    for line in corpus:
        if not _DLL_HIJACK_LINE_RE.search(line):
            continue
        z, d = _pick_zip_dll(line)
        zip_name = zip_name or z
        dll_name = dll_name or d
        for path_match in _WIN_PATH_RE.finditer(line):
            path = path_match.group(1).rstrip(".")
            if z and z.lower() in path.lower():
                drop_path = _drop_path_from_zip_path(path, z)
            elif path.lower().endswith(".log"):
                monitor_log_path = path
            elif d and d.lower() in path.lower() and "\\" in path:
                drop_path = path.rsplit("\\", 1)[0]
        task_match = _TASK_NAME_RE.search(line)
        if task_match:
            task_hint = task_hint or task_match.group(1).strip()

    if not zip_name and not dll_name:
        for line in corpus:
            z, d = _pick_zip_dll(line)
            zip_name = zip_name or z
            dll_name = dll_name or d
            for path_match in _WIN_PATH_RE.finditer(line):
                path = path_match.group(1).rstrip(".")
                if z and z.lower() in path.lower():
                    drop_path = drop_path or _drop_path_from_zip_path(path, z)

    if not zip_name and not dll_name:
        if com_task_output.strip():
            return intel_from_com_tasks(com_task_output)
        return None

    zip_name = zip_name or "payload.zip"
    dll_name = dll_name or "payload.dll"
    if not drop_path:
        # prefer a directory mentioned in the same line as the zip
        for line in corpus:
            z, _ = _pick_zip_dll(line)
            if z:
                for path_match in _WIN_PATH_RE.finditer(line):
                    path = path_match.group(1).rstrip(".")
                    if z.lower() in path.lower():
                        drop_path = _drop_path_from_zip_path(path, z)
                        break
                if drop_path:
                    break
        if not drop_path:
            for line in corpus:
                for path_match in _WIN_PATH_RE.finditer(line):
                    path = path_match.group(1).rstrip(".")
                    if dll_name and dll_name.lower() in path.lower():
                        drop_path = path.rsplit("\\", 1)[0]
                        break
                if drop_path:
                    break
    if not drop_path:
        drop_path = r"C:\ProgramData"

    com_filter = task_hint or (zip_name.split(".")[0] if zip_name else None)

    return HijackIntel(
        payload_zip=zip_name,
        payload_dll=dll_name,
        drop_path=drop_path,
        monitor_log_path=monitor_log_path,
        task_name_hint=task_hint,
        com_task_filter=com_filter,
    )


def guess_run_as_from_log(text: str) -> str:
    for line in text.splitlines():
        loaded = re.search(
            r"(?:[\w.-]+\\)?([\w.-]+)\s+loaded\s+[\w.-]+\.dll",
            line,
            re.I,
        )
        if loaded:
            user = loaded.group(1).strip()
            if user.lower() not in {"system", "localservice", "networkservice"}:
                return user
    match = _RUN_AS_RE.search(text)
    return match.group(1) if match else ""
