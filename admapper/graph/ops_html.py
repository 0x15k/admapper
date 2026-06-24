"""AD Ops dashboard — HTML shell, CSS, and client-side JavaScript."""

from __future__ import annotations

import json
from pathlib import Path

from admapper.graph.ops_payload import _esc, build_ops_payload

def build_ops_html(
    ws_path: Path,
    *,
    workspace: str,
    domain: str | None,
    owned_users: list[str] | None = None,
    pivot_user: str | None = None,
    api_mode: bool = False,
) -> str:
    data = build_ops_payload(
        ws_path,
        workspace=workspace,
        domain=domain,
        owned_users=owned_users,
        pivot_user=pivot_user,
    )
    payload_json = json.dumps(data)
    api_flag = "true" if api_mode else "false"

    return f"""<!DOCTYPE html>
<html lang="es">
<head>
  <meta charset="utf-8"/>
  <meta name="viewport" content="width=device-width, initial-scale=1"/>
  <title>AD Ops — {_esc(workspace)}</title>
  <link rel="preconnect" href="https://fonts.googleapis.com"/>
  <link href="https://fonts.googleapis.com/css2?family=IBM+Plex+Mono:wght@400;600&family=IBM+Plex+Sans:wght@400;600;700&display=swap" rel="stylesheet"/>
  <script src="https://unpkg.com/vis-network@9.1.9/standalone/umd/vis-network.min.js"></script>
  <style>
    :root {{
      --bg: #080b10;
      --panel: #0f1419;
      --border: rgba(255,255,255,0.07);
      --text: #e8edf4;
      --muted: #7a8699;
      --accent: #3dffcf;
      --accent-dim: rgba(61,255,207,0.12);
      --warn: #ffb020;
      --danger: #ff4d6a;
      --owned: #3dffcf;
      --pivot: #ff8c42;
      --success: #22c55e;
    }}
    * {{ box-sizing: border-box; margin: 0; padding: 0; }}
    body {{
      font-family: 'IBM Plex Sans', system-ui, sans-serif;
      background: var(--bg);
      color: var(--text);
      min-height: 100vh;
      overflow: hidden;
    }}
    /* ── screens ── */
    .screen {{ position: fixed; inset: 0; display: none; flex-direction: column; z-index: 10; }}
    .screen.active {{ display: flex; }}
    #screen-boot {{
      background: #050708;
      flex-direction: column;
    }}
    .boot-wrap {{
      flex: 1;
      display: flex;
      flex-direction: column;
      max-width: 900px;
      width: 100%;
      margin: 0 auto;
      padding: 1.5rem;
    }}
    .boot-banner {{
      font-family: 'IBM Plex Mono', monospace;
      font-size: 0.7rem;
      color: var(--muted);
      letter-spacing: 0.12em;
      margin-bottom: 0.75rem;
    }}
    #boot-terminal {{
      flex: 1;
      background: #0a0e12;
      border: 1px solid var(--border);
      padding: 1rem;
      font-family: 'IBM Plex Mono', monospace;
      font-size: 0.78rem;
      line-height: 1.5;
      color: #9ae6d5;
      overflow-y: auto;
      min-height: 280px;
    }}
    #boot-terminal .line-error {{ color: var(--danger); }}
    #boot-terminal .line-cmd {{ color: var(--accent); }}
    #boot-terminal .line-phase {{ color: var(--warn); }}
    .boot-input-row {{
      display: flex;
      align-items: center;
      gap: 0.5rem;
      margin-top: 0.75rem;
      font-family: 'IBM Plex Mono', monospace;
      font-size: 0.85rem;
    }}
  .boot-input-row span {{ color: var(--accent); }}
    #boot-ip {{
      flex: 1;
      background: transparent;
      border: none;
      border-bottom: 1px solid var(--accent);
      color: var(--text);
      font-family: inherit;
      font-size: inherit;
      padding: 0.35rem 0;
      outline: none;
    }}
    /* ── HQ room (GBA pixel) ── */
    #screen-hq {{
      background: #101018;
      align-items: center;
      justify-content: center;
    }}
    .hq-wrap {{
      display: flex;
      flex-direction: column;
      width: min(980px, 98vw);
      height: min(94vh, 680px);
      gap: 0.4rem;
    }}
    .hq-header {{
      font-family: 'IBM Plex Mono', monospace;
      font-size: 0.68rem;
      color: #888;
      letter-spacing: 0.1em;
      text-align: center;
    }}
    .hq-stage {{
      flex: 1;
      display: flex;
      align-items: center;
      justify-content: center;
      border: 4px solid #383838;
      border-radius: 2px;
      background: #000;
      box-shadow: 0 0 0 2px #101010, 0 12px 40px rgba(0,0,0,0.55);
      overflow: hidden;
      position: relative;
    }}
    #hq-canvas {{
      display: block;
      width: 100%;
      height: 100%;
      object-fit: contain;
      image-rendering: pixelated;
      image-rendering: crisp-edges;
    }}
    .hq-fade {{
      position: absolute;
      inset: 0;
      background: #000;
      opacity: 0;
      pointer-events: none;
      transition: opacity 0.5s ease;
      z-index: 25;
    }}
    .hq-fade.active {{ opacity: 1; pointer-events: all; }}
    .hq-hud {{
      display: flex;
      justify-content: space-between;
      align-items: center;
      font-family: 'IBM Plex Mono', monospace;
      font-size: 0.68rem;
      color: #888;
      padding: 0 0.25rem;
    }}
    .hq-prompt {{
      color: #f8f8f0;
      min-height: 1.2em;
      letter-spacing: 0.04em;
      text-shadow: 1px 1px 0 #181818;
    }}
    .hq-prompt.active {{ animation: hq-blink 0.8s step-end infinite; }}
    @keyframes hq-blink {{ 50% {{ opacity: 0.4; }} }}
    .hq-dialog {{
      position: absolute;
      left: 50%;
      bottom: 8%;
      transform: translateX(-50%);
      width: min(420px, 92%);
      background: #f8f8f0;
      border: 3px solid #383838;
      border-radius: 6px;
      padding: 0.75rem 0.9rem 0.65rem;
      font-family: 'IBM Plex Mono', monospace;
      font-size: 0.76rem;
      z-index: 20;
      color: #282828;
      box-shadow: inset -2px -2px 0 #a8a8a0, inset 2px 2px 0 #fff, 0 6px 0 #181818;
    }}
    .hq-dialog.hidden {{ display: none; }}
    .hq-dialog p {{ margin-bottom: 0.55rem; line-height: 1.5; }}
    .hq-dialog-btns {{ display: flex; gap: 0.45rem; justify-content: flex-end; }}
    .hq-dialog-btns button {{
      font-family: inherit;
      font-size: 0.72rem;
      padding: 0.3rem 0.7rem;
      border: 2px solid #383838;
      background: #e0e0d8;
      color: #282828;
      cursor: pointer;
      border-radius: 4px;
      box-shadow: inset -1px -1px 0 #a0a0a0, inset 1px 1px 0 #fff;
    }}
    .hq-dialog-btns button.primary {{
      background: #c8e8e0;
      border-color: #286860;
    }}
    .hq-dialog-btns button:hover {{ filter: brightness(1.05); }}
    .map-tabs {{
      display: flex; gap: 0.5rem; margin-left: 1rem;
    }}
    .map-tab {{
      font-family: 'IBM Plex Mono', monospace;
      font-size: 0.65rem;
      padding: 0.25rem 0.6rem;
      border: 1px solid var(--border);
      background: transparent;
      color: var(--muted);
      cursor: pointer;
    }}
    .map-tab.active {{ border-color: var(--accent); color: var(--accent); }}
    .notes-panel {{ padding: 0.65rem 0.85rem; }}
    .notes-doc {{
      font-family: 'IBM Plex Mono', monospace;
      font-size: 0.72rem;
      line-height: 1.55;
    }}
    .notes-doc .note-h2 {{
      font-size: 0.62rem; text-transform: uppercase; letter-spacing: 0.14em;
      color: var(--muted); margin: 1rem 0 0.35rem;
    }}
    .notes-doc .note-h2:first-child {{ margin-top: 0; }}
    .notes-doc .note-h3 {{ font-size: 0.72rem; font-weight: 600; margin: 0.35rem 0; color: var(--text); }}
    .note-section {{ margin-bottom: 0.55rem; padding-bottom: 0.55rem; border-bottom: 1px solid var(--border); }}
    .note-section:last-child {{ border-bottom: none; }}
    .note-header {{
      font-size: 0.82rem; font-weight: 600; color: var(--text);
      margin: 0 0 0.65rem; padding-bottom: 0.45rem;
      border-bottom: 1px dashed var(--border);
    }}
    .note-header .note-sub {{ font-weight: 400; color: var(--muted); font-size: 0.68rem; }}
    .note-kv {{
      display: flex; flex-wrap: wrap; gap: 0.35rem 0.5rem;
      align-items: baseline; margin: 0.22rem 0;
      font-size: 0.71rem;
    }}
    .note-kv .note-key {{ color: var(--muted); min-width: 4.5rem; flex-shrink: 0; }}
    .note-kv .note-arr {{ color: var(--accent); flex-shrink: 0; }}
    .note-kv .note-val {{ color: var(--text); word-break: break-word; }}
    .note-kv .note-val.dim {{ color: var(--muted); }}
    .note-kv .note-val.ok {{ color: var(--owned); }}
    .note-kv .note-val.warn {{ color: var(--warn); }}
    .note-kv.indent {{ padding-left: 0.75rem; }}
    .note-todo {{ margin: 0.2rem 0; color: var(--warn); }}
    .note-todo.done {{ color: var(--muted); text-decoration: line-through; }}
    .note-block-label {{
      font-size: 0.62rem; letter-spacing: 0.12em; text-transform: uppercase;
      color: var(--accent); margin: 0.65rem 0 0.25rem;
    }}
    .note-callout {{
      background: #121820; border-left: 3px solid var(--accent);
      padding: 0.55rem 0.7rem; margin: 0.45rem 0; font-size: 0.74rem;
    }}
    .note-callout.warn {{ border-left-color: var(--warn); background: rgba(255,176,32,0.06); }}
    .note-callout.focus {{ border-left-color: var(--pivot); background: rgba(255,140,66,0.08); }}
    .note-callout.danger {{ border-left-color: var(--danger); background: rgba(255,77,106,0.06); }}
    .notes-doc details {{ margin: 0.45rem 0; }}
    .notes-doc details > summary {{
      cursor: pointer; font-size: 0.7rem; color: var(--muted);
      letter-spacing: 0.06em; list-style: none;
    }}
    .notes-doc details > summary::-webkit-details-marker {{ display: none; }}
    .notes-doc details > summary::before {{ content: '▸ '; color: var(--accent); }}
    .notes-doc details[open] > summary::before {{ content: '▾ '; }}
    .notes-doc details[open] > summary {{ color: var(--accent); margin-bottom: 0.45rem; }}
    .notes-title {{
      font-size: 0.62rem;
      letter-spacing: 0.16em; color: var(--muted); margin-bottom: 0.5rem;
    }}
    .note-inline {{ font-size: 0.68rem; color: var(--muted); }}
    /* ── play HUD ── */
    .top {{
      display: flex; align-items: center; justify-content: space-between;
      padding: 0.75rem 1.25rem;
      border-bottom: 1px solid var(--border);
      background: var(--panel);
      flex-shrink: 0;
    }}
    .brand {{ font-family: 'IBM Plex Mono', monospace; font-weight: 600; font-size: 0.95rem; letter-spacing: 0.12em; color: var(--accent); }}
    .brand span {{ color: var(--muted); font-weight: 400; }}
    .meta {{ font-size: 0.8rem; color: var(--muted); text-align: right; }}
    .meta strong {{ color: var(--text); }}
    .framework-bar {{
      padding: 0.2rem 0.75rem;
      font-size: 0.65rem;
      color: var(--muted);
      border-bottom: 1px solid var(--border);
      font-family: 'IBM Plex Mono', monospace;
    }}
    .phase .ref {{
      font-size: 0.55rem;
      color: var(--muted);
      margin-top: 2px;
      max-width: 7rem;
      overflow: hidden;
      text-overflow: ellipsis;
      white-space: nowrap;
    }}
    .study-map details {{ margin-bottom: 0.75rem; }}
    .study-map summary {{ cursor: pointer; font-size: 0.75rem; color: var(--accent); }}
    .study-map table {{ width: 100%; font-size: 0.65rem; border-collapse: collapse; }}
    .study-map td, .study-map th {{ border: 1px solid var(--border); padding: 2px 4px; vertical-align: top; }}
    .phases {{
      display: flex; gap: 0; padding: 0.6rem 1rem;
      background: #0a0e14;
      border-bottom: 1px solid var(--border);
      overflow-x: auto;
      flex-shrink: 0;
    }}
    .phase {{
      flex: 1; min-width: 100px; padding: 0.5rem 0.6rem;
      border-right: 1px solid var(--border);
      position: relative;
      transition: background 0.4s, opacity 0.4s;
    }}
    .phase:last-child {{ border-right: none; }}
    .phase .code {{ font-family: 'IBM Plex Mono', monospace; font-size: 0.62rem; letter-spacing: 0.08em; color: var(--muted); }}
    .phase .title {{ font-size: 0.68rem; margin-top: 0.15rem; font-weight: 600; }}
    .phase.done .code, .phase.done .title {{ color: var(--owned); }}
    .phase.done {{ animation: unlock 0.6s ease; }}
    .phase.active {{ background: var(--accent-dim); box-shadow: inset 0 -2px 0 var(--accent); animation: pulse-phase 2s infinite; }}
    .phase.active .code {{ color: var(--accent); }}
    .phase.locked {{ opacity: 0.4; }}
    .hud-body {{
      display: grid;
      grid-template-columns: 300px 1fr 280px;
      grid-template-rows: 1fr 180px;
      flex: 1;
      min-height: 0;
      height: calc(100vh - 118px);
    }}
    .panel {{
      border-right: 1px solid var(--border);
      overflow-y: auto;
      padding: 1rem;
      background: var(--panel);
      min-height: 0;
    }}
    .panel-right {{ border-right: none; border-left: 1px solid var(--border); }}
    .panel h3 {{
      font-size: 0.65rem; text-transform: uppercase; letter-spacing: 0.14em;
      color: var(--muted); margin-bottom: 0.65rem;
    }}
    .graph-wrap {{
      position: relative;
      min-height: 0;
      height: 100%;
      background: var(--bg);
      overflow: hidden;
    }}
    #graph {{
      width: 100%;
      height: 100%;
      min-height: 320px;
    }}
    .scan-overlay {{
      pointer-events: none;
      position: absolute; inset: 0;
      background: repeating-linear-gradient(
        0deg,
        transparent,
        transparent 2px,
        rgba(61,255,207,0.03) 2px,
        rgba(61,255,207,0.03) 4px
      );
      animation: scan-sweep 3s linear infinite;
      opacity: 0;
      transition: opacity 0.3s;
    }}
    .scan-overlay.active {{ opacity: 1; }}
    .terminal-wrap {{
      grid-column: 1 / -1;
      border-top: 1px solid var(--border);
      background: #060809;
      display: flex;
      flex-direction: column;
      min-height: 0;
    }}
    .terminal-header {{
      display: flex; align-items: center; justify-content: space-between;
      padding: 0.35rem 0.75rem;
      font-family: 'IBM Plex Mono', monospace;
      font-size: 0.65rem;
      color: var(--muted);
      border-bottom: 1px solid var(--border);
    }}
    .progress-bar {{
      height: 3px;
      background: var(--border);
      overflow: hidden;
      display: none;
    }}
    .progress-bar.active {{ display: block; }}
    .progress-bar span {{
      display: block; height: 100%; width: 30%;
      background: var(--accent);
      animation: progress-indeterminate 1.2s ease-in-out infinite;
    }}
    #terminal {{
      flex: 1;
      overflow-y: auto;
      padding: 0.5rem 0.75rem;
      font-family: 'IBM Plex Mono', monospace;
      font-size: 0.72rem;
      line-height: 1.45;
      color: #9ae6d5;
      white-space: pre-wrap;
      word-break: break-all;
    }}
    #terminal .line-cmd {{ color: var(--accent); }}
    #terminal .line-error {{ color: var(--danger); }}
    #terminal .line-phase {{ color: var(--warn); }}
    #terminal .cursor {{
      display: inline-block;
      width: 8px; height: 1em;
      background: var(--accent);
      animation: blink 1s step-end infinite;
      vertical-align: text-bottom;
    }}
    .objective {{
      background: #121820;
      border: 1px solid var(--border);
      border-left: 3px solid var(--accent);
      padding: 0.85rem;
      margin-bottom: 1rem;
    }}
    .objective h2 {{ font-size: 0.85rem; margin-bottom: 0.35rem; }}
    .objective .tech {{ font-family: 'IBM Plex Mono', monospace; font-size: 0.72rem; color: var(--accent); margin-bottom: 0.5rem; }}
    .objective code {{
      display: block; font-family: 'IBM Plex Mono', monospace; font-size: 0.68rem;
      color: var(--muted); word-break: break-all; margin-top: 0.5rem;
      padding: 0.4rem; background: var(--bg); border-radius: 4px;
    }}
    .blocker {{
      border-left-color: var(--danger);
      background: rgba(255,77,106,0.08);
      margin-bottom: 1rem;
      padding: 0.65rem;
      font-size: 0.78rem;
    }}
    .book-reader {{
      position: absolute; inset: 0; overflow-y: auto;
      background: var(--bg); padding: 1.25rem 1.5rem 4rem;
      font-size: 0.88rem; line-height: 1.55;
    }}
    .book-reader[hidden] {{ display: none !important; }}
    .book-header {{ border-bottom: 1px solid var(--border); padding-bottom: 0.75rem; margin-bottom: 1rem; }}
    .book-header h1 {{ font-size: 1.15rem; margin-bottom: 0.25rem; }}
    .book-chapter {{ font-family: 'IBM Plex Mono', monospace; font-size: 0.68rem; color: var(--accent); letter-spacing: 0.1em; }}
    .book-nav {{
      position: sticky; bottom: 0; display: flex; gap: 0.5rem; justify-content: space-between;
      padding: 0.75rem 0; margin-top: 1.5rem; border-top: 1px solid var(--border);
      background: linear-gradient(transparent, var(--bg) 20%);
    }}
    .book-nav button {{
      font-family: 'IBM Plex Mono', monospace; font-size: 0.72rem;
      padding: 0.5rem 0.85rem; border: 1px solid var(--border);
      background: var(--panel); color: var(--text); cursor: pointer;
    }}
    .book-nav button:hover {{ border-color: var(--accent); color: var(--accent); }}
    .book-toc {{ margin-bottom: 1rem; }}
    .book-toc button {{
      display: block; width: 100%; text-align: left; margin: 0.2rem 0;
      padding: 0.35rem 0.5rem; font-size: 0.75rem; border: none;
      background: transparent; color: var(--muted); cursor: pointer;
    }}
    .book-toc button:hover, .book-toc button.active {{ color: var(--accent); }}
    .book-section {{ margin-bottom: 1rem; }}
    .book-section p {{ color: var(--text); margin-bottom: 0.65rem; }}
    .book-section ul {{ margin-left: 1.1rem; color: var(--muted); }}
    .book-section li {{ margin-bottom: 0.35rem; }}
    .book-section table {{ width: 100%; border-collapse: collapse; font-size: 0.78rem; margin: 0.5rem 0; }}
    .book-section th, .book-section td {{ border: 1px solid var(--border); padding: 0.4rem 0.5rem; text-align: left; }}
    .book-section th {{ background: var(--panel); color: var(--accent); }}
    .book-section pre {{
      font-family: 'IBM Plex Mono', monospace; font-size: 0.68rem;
      background: #050708; border: 1px solid var(--border); padding: 0.75rem;
      overflow-x: auto; color: #a8b8cc; margin: 0.5rem 0;
    }}
    .book-diagram {{ margin: 0.75rem 0; overflow-x: auto; }}
    .book-diagram svg {{ max-width: 100%; height: auto; }}
    .book-meta {{ font-size: 0.72rem; color: var(--muted); margin-top: 0.5rem; }}
    .action-btn {{
      display: block;
      width: 100%;
      margin: 0.5rem 0;
      padding: 0.75rem 1rem;
      font-family: 'IBM Plex Mono', monospace;
      font-size: 0.75rem;
      letter-spacing: 0.08em;
      font-weight: 600;
      border: 1px solid var(--accent);
      background: var(--accent-dim);
      color: var(--accent);
      cursor: pointer;
      transition: all 0.15s;
    }}
    .action-btn:hover:not(:disabled) {{ background: rgba(61,255,207,0.22); }}
    .action-btn:disabled {{ opacity: 0.35; cursor: not-allowed; }}
    .action-btn.running {{ animation: pulse-phase 1s infinite; }}
    .mission-card {{
      background: linear-gradient(135deg, rgba(61,255,207,0.08), rgba(99,102,241,0.06));
      border: 1px solid rgba(61,255,207,0.35);
      padding: 1rem;
      margin-bottom: 1rem;
      animation: pulse-phase 2.5s ease-in-out infinite;
    }}
    .mission-card h2 {{ font-size: 0.7rem; letter-spacing: 0.14em; color: var(--warn); margin-bottom: 0.4rem; }}
    .mission-card .mission-title {{ font-size: 0.95rem; font-weight: 700; margin-bottom: 0.35rem; }}
    .mission-card .mission-reward {{ font-size: 0.72rem; color: var(--owned); margin-top: 0.5rem; }}
    .mission-card .mission-reward::before {{ content: 'IMPACTO: '; color: var(--muted); }}
    .mission-btn {{
      border-color: var(--warn);
      color: var(--warn);
      background: rgba(255,176,32,0.12);
      font-size: 0.8rem;
      margin-top: 0.65rem;
    }}
    .mission-btn:hover:not(:disabled) {{ background: rgba(255,176,32,0.25); }}
    .quest-list li {{ cursor: pointer; transition: background 0.15s; }}
    .quest-list li:hover, .quest-list li.selected {{ background: var(--accent-dim); }}
    .quest-list li.selected {{ border-left: 2px solid var(--accent); padding-left: 0.35rem; }}
    .phase-tools {{ margin-top: 1rem; opacity: 0.85; }}
    .phase-tools summary {{ cursor: pointer; font-size: 0.72rem; color: var(--muted); }}
    .cred-form input {{
      width: 100%;
      margin: 0.35rem 0;
      padding: 0.5rem;
      background: var(--bg);
      border: 1px solid var(--border);
      color: var(--text);
      font-family: 'IBM Plex Mono', monospace;
      font-size: 0.75rem;
    }}
    .chip {{
      display: inline-block;
      font-family: 'IBM Plex Mono', monospace;
      font-size: 0.68rem;
      padding: 0.2rem 0.5rem;
      border-radius: 4px;
      margin: 0.15rem 0.25rem 0.15rem 0;
      border: 1px solid var(--border);
    }}
    .chip.owned {{ border-color: var(--owned); color: var(--owned); }}
    .chip.pivot {{ border-color: var(--pivot); color: var(--pivot); }}
    .chip.pivot-active {{ border-color: var(--pivot); background: rgba(255,140,66,0.15); color: var(--pivot); }}
    .chip.pivot-btn {{ cursor: pointer; }}
    .chip.pivot-btn:hover {{ background: rgba(255,140,66,0.12); }}
    .cred-form label {{ display: block; font-size: 0.68rem; color: var(--muted); margin: 0.5rem 0 0.25rem; }}
    .chip.valid {{ color: var(--owned); }}
    .chip.focus-active {{ border-color: var(--warn); color: var(--warn); box-shadow: 0 0 0 1px var(--warn); }}
    .action-btn.secondary {{ background: transparent; border: 1px solid var(--border); color: var(--muted); }}
    .action-btn.secondary:hover {{ border-color: var(--accent); color: var(--text); }}
    #ui-toast {{
      position: fixed; bottom: 5.5rem; right: 1rem; max-width: 360px;
      padding: 0.65rem 1rem; background: #1a1218; border: 1px solid var(--danger);
      color: var(--danger); font-size: 0.8rem; z-index: 50; display: none;
    }}
    #ui-toast.ok {{ border-color: var(--success); color: var(--success); background: #0f1a14; }}
    .node-inspector {{
      background: var(--accent-dim); border: 1px solid var(--border);
      padding: 0.75rem; margin-bottom: 1rem; border-radius: 4px;
    }}
    .chip.invalid {{ color: var(--danger); }}
    .list {{ list-style: none; font-size: 0.78rem; }}
    .list li {{ padding: 0.45rem 0; border-bottom: 1px solid var(--border); line-height: 1.35; }}
    .list .sub {{ color: var(--muted); font-size: 0.7rem; font-family: 'IBM Plex Mono', monospace; }}
    .hl {{ font-size: 0.75rem; color: var(--muted); margin-bottom: 0.35rem; }}
    .hl::before {{ content: '▸ '; color: var(--accent); }}
    body.flash-success {{ animation: flash-green 0.5s; }}
    body.flash-error {{ animation: shake 0.4s; }}
    @keyframes glitch {{
      0%, 90%, 100% {{ transform: none; text-shadow: 0 0 40px rgba(61,255,207,0.4); }}
      92% {{ transform: translate(-2px, 1px); text-shadow: 2px 0 var(--danger); }}
      94% {{ transform: translate(2px, -1px); text-shadow: -2px 0 var(--warn); }}
    }}
    @keyframes blink {{ 50% {{ opacity: 0; }} }}
    @keyframes pulse-phase {{ 0%, 100% {{ opacity: 1; }} 50% {{ opacity: 0.75; }} }}
    @keyframes unlock {{ 0% {{ transform: scale(1); }} 50% {{ transform: scale(1.03); background: rgba(34,197,94,0.15); }} 100% {{ transform: scale(1); }} }}
    @keyframes scan-sweep {{ 0% {{ background-position: 0 0; }} 100% {{ background-position: 0 100px; }} }}
    @keyframes progress-indeterminate {{ 0% {{ transform: translateX(-100%); }} 100% {{ transform: translateX(400%); }} }}
    @keyframes flash-green {{ 0% {{ box-shadow: inset 0 0 0 0 transparent; }} 30% {{ box-shadow: inset 0 0 80px rgba(34,197,94,0.15); }} 100% {{ box-shadow: none; }} }}
    @keyframes shake {{ 0%, 100% {{ transform: translateX(0); }} 25% {{ transform: translateX(-4px); }} 75% {{ transform: translateX(4px); }} }}
    @media (max-width: 1100px) {{
      .hud-body {{ grid-template-columns: 1fr; grid-template-rows: auto minmax(280px, 40vh) auto 160px; }}
      .panel-right {{ border-left: none; border-top: 1px solid var(--border); }}
    }}
  </style>
</head>
<body>
  <!-- BLACKBOX BOOT -->
  <div id="screen-boot" class="screen active">
    <div class="boot-wrap">
      <div class="boot-banner">AD OPS // BLACKBOX ENGAGEMENT — sin intel previa</div>
      <div id="boot-terminal"></div>
      <div class="boot-input-row">
        <span>target&gt;</span>
        <input id="boot-ip" type="text" inputmode="decimal" autocomplete="off" spellcheck="false" placeholder="10.x.x.x"/>
      </div>
    </div>
  </div>

  <!-- HQ ROOM (2D) -->
  <div id="screen-hq" class="screen">
    <div class="hq-wrap">
      <div class="hq-header">AD OPS // OPERATOR HQ — usa la laptop para trabajar</div>
      <div class="hq-stage" id="hq-stage">
        <canvas id="hq-canvas" width="640" height="448" aria-label="Habitación operador"></canvas>
        <div id="hq-fade" class="hq-fade"></div>
        <div id="hq-dialog" class="hq-dialog hidden">
          <p id="hq-dialog-text">¿Abrir AD OPS en la laptop?</p>
          <div class="hq-dialog-btns">
            <button type="button" id="hq-dialog-no">No</button>
            <button type="button" class="primary" id="hq-dialog-yes">Sí — sentarse</button>
          </div>
        </div>
      </div>
      <div class="hq-hud">
        <div id="hq-prompt" class="hq-prompt"></div>
        <div class="hq-hint">WASD / flechas · E interactuar</div>
      </div>
    </div>
  </div>

  <!-- PLAY HUD -->
  <div id="screen-play" class="screen">
    <header class="top">
      <div class="brand">AD OPS <span>// {_esc(workspace)}</span></div>
      <div class="map-tabs">
        <button class="map-tab" id="tab-hq" type="button">HQ</button>
        <button class="map-tab active" id="tab-network" type="button">NETWORK</button>
        <button class="map-tab" id="tab-ad" type="button">AD MAP</button>
        <button class="map-tab" id="tab-manual" type="button">MANUAL</button>
      </div>
      <div class="meta" id="hud-meta"></div>
    </header>
    <div class="framework-bar" id="framework-bar"></div>
    <nav class="phases" id="phases"></nav>
    <div class="hud-body">
      <aside class="panel" id="left"></aside>
      <div class="graph-wrap">
        <div class="scan-overlay" id="scan-overlay"></div>
        <div id="graph"></div>
        <div id="book-reader" class="book-reader" hidden></div>
      </div>
      <aside class="panel panel-right notes-panel" id="right"></aside>
      <div id="ui-toast"></div>
      <div class="terminal-wrap">
        <div class="terminal-header">
          <span>TERMINAL // admapper</span>
          <span id="op-status">IDLE</span>
        </div>
        <div class="progress-bar" id="progress-bar"><span></span></div>
        <div id="terminal"><span class="cursor"></span></div>
      </div>
    </div>
  </div>

  <script>
    const API_MODE = {api_flag};
    let OPS = {payload_json};
    let network = null;
    let nodeData = null;
    let edgeData = null;
    let opRunning = false;
    let evtSource = null;
    let screen = 'boot';
    let selectedMissionId = null;
    let viewMode = 'network';
    let bookPageIdx = 0;
    let graphFocus = null;
    let infraFocus = null;
    let lastGraphSig = '';
    let graphPulseDone = false;
    let hqBuilt = false;
    let hqAnimId = null;
    let hqKeys = {{}};
    let hqNearId = null;
    let hqCanvas = null;
    let hqCtx = null;
    let hqStatic = null;
    let hqWalkTick = 0;
    let hqPlayer = {{ tx: 3.6, ty: 7.5, dir: 'up', moving: false, frame: 0 }};

    const HQ = {{
      TILE: 16,
      COLS: 20,
      ROWS: 14,
      SCALE: 3,
      get W() {{ return this.COLS * this.TILE; }},
      get H() {{ return this.ROWS * this.TILE; }},
      laptop: {{ tx: 3.5, ty: 6.4, label: 'Laptop AD OPS' }},
      spawnDesk: {{ tx: 3.6, ty: 7.45 }},
      spawnDefault: {{ tx: 10, ty: 9.8 }},
      interactables: [
        {{ id: 'laptop', tx: 3.5, ty: 6.2, r: 1.65, label: 'Laptop AD OPS', face: 'up' }},
        {{ id: 'bed', tx: 16.2, ty: 10.5, r: 1.5, label: 'Cama', flavor: 'Mejor no dormir — el engagement no se pentestea solo.' }},
        {{ id: 'shelf', tx: 12.5, ty: 5.4, r: 1.25, label: 'Estantería', flavor: 'CRTP, CRTE, OSCP… La laptop va más rápido.' }},
        {{ id: 'tv', tx: 16.2, ty: 5.6, r: 1.15, label: 'TV', flavor: 'Solo estática. El mapa real está en AD OPS.' }},
      ],
    }};

    const HQ_PAL = {{
      '.': null, B: '#181020', W: '#e8e4d8', W2: '#c8c4b8', WL: '#b0aca0', BB: '#2860a8', F1: '#8b5a2b',
      F2: '#a06830', F3: '#6b4226', R1: '#c83830', R2: '#e8d8a0', RF: '#a02828', D1: '#d8b878', D2: '#b89858',
      M: '#282830', S: '#1a3830', G: '#58b858', G2: '#409040', P: '#f0c8a8', H: '#503018', SH: '#4870c0',
      SH2: '#3860b0', BD: '#c08050', BK: '#f8f8f0', PV: '#e070a8', PV2: '#c05890', K: '#404048', C: '#58b8e8',
      Y: '#f8e060', O: '#f09030', PU: '#8868c8', T: '#40e8c8', L: '#98d0f8', DR: '#e8c848', DR2: '#c8a828',
      RD: '#d04038', WH: '#f8f8f8',
    }};

    HQ.collision = (() => {{
      const g = Array.from({{ length: HQ.ROWS }}, () => Array(HQ.COLS).fill(0));
      const block = (x0, y0, x1, y1) => {{
        for (let y = y0; y <= y1; y++) for (let x = x0; x <= x1; x++) if (g[y] && g[y][x] !== undefined) g[y][x] = 1;
      }};
      block(0, 0, 19, 2);
      for (let y = 0; y < HQ.ROWS; y++) {{ g[y][0] = 1; g[y][19] = 1; }}
      block(1, 4, 7, 5);
      block(10, 4, 11, 5);
      block(12, 4, 14, 5);
      block(15, 4, 17, 6);
      block(16, 2, 18, 4);
      block(14, 9, 18, 12);
      return g;
    }})();

    const $ = (id) => document.getElementById(id);

    function activePivot() {{
      return ((OPS.player || {{}}).pivot || '').toLowerCase();
    }}

    function lensForUser(username) {{
      if (!username) return {{}};
      const ident = (OPS.selectable_identities || []).find(
        i => i.username.toLowerCase() === username.toLowerCase()
      );
      if (ident && (ident.lens || ident.view_lens)) return ident.lens || ident.view_lens;
      const pth = (OPS.pth_sessions || []).find(
        p => p.account.toLowerCase() === username.toLowerCase()
      );
      if (pth) {{
        return {{
          username: pth.account,
          status: 'machine_pth',
          status_label: 'gMSA / máquina — WinRM PTH (sin password LDAP)',
          read_only: false,
          is_machine: true,
          nthash: pth.nthash,
          winrm_cmd: pth.winrm_cmd,
          access_matrix: [pth.account, 'skip', 'skip', 'skip', 'sí*', 'hash gMSA — WinRM PTH'],
        }};
      }}
      if (username.toLowerCase() === activePivot()) return OPS.identity_lens || {{}};
      return {{}};
    }}

    function getDisplayLens() {{
      const u = graphFocus || (OPS.player || {{}}).pivot;
      return lensForUser(u);
    }}

    function isInspectingOther() {{
      if (!graphFocus) return false;
      return graphFocus.toLowerCase() !== activePivot();
    }}

    function getDisplayActions() {{
      let actions = (OPS.actions || []).filter(a => a.enabled !== false);
      if (isInspectingOther()) {{
        const globalIds = new Set(['scan', 'cred', 'enum', 'loot', 'acls']);
        actions = actions.filter(a => globalIds.has(a.id));
      }}
      return actions;
    }}

    function getDisplayQuests() {{
      if (isInspectingOther()) return [];
      return (OPS.quests || []).filter(q => q.verified);
    }}

    function getDisplayAttackPaths() {{
      if (isInspectingOther()) return [];
      return OPS.attack_paths || [];
    }}

    function showUiToast(msg, ok) {{
      const el = $('ui-toast');
      if (!el) return;
      el.textContent = msg;
      el.className = ok ? 'ok' : '';
      el.style.display = msg ? 'block' : 'none';
      if (msg) setTimeout(() => {{ el.style.display = 'none'; }}, ok ? 2200 : 4500);
    }}

    function focusIdentity(username) {{
      if (!username) return;
      const ident = (OPS.selectable_identities || []).find(
        i => i.username.toLowerCase() === username.toLowerCase()
      );
      if (!ident) return;
      graphFocus = ident.username;
      infraFocus = null;
      selectedMissionId = null;
      if (viewMode !== 'ad') setMapTab('ad');
      else {{
        renderAll();
        highlightIdentityGraph();
      }}
    }}

    function clearGraphFocus() {{
      graphFocus = null;
      infraFocus = null;
      selectedMissionId = null;
      renderAll();
      highlightIdentityGraph();
    }}

    async function operarComo(username) {{
      if (!username) return;
      const pth = (OPS.pth_sessions || []).find(
        p => p.account.toLowerCase() === username.toLowerCase()
      );
      if (pth) {{
        await runWinrmPth(pth.account);
        return;
      }}
      const ident = (OPS.selectable_identities || []).find(
        i => i.username.toLowerCase() === username.toLowerCase()
      );
      if (!ident) {{
        showUiToast('Sin perfil para ' + username);
        return;
      }}
      if (ident.selectable === 'view') {{
        showUiToast(username + ' es solo lectura — enum sin credencial');
        return;
      }}
      if (ident.selectable === 'verify') {{
        const el = $('cred-user');
        if (el) el.value = ident.username;
        graphFocus = ident.username;
        renderLeft();
        showUiToast('Verifica la pista en el formulario y pulsa AUTENTICAR', true);
        return;
      }}
      await setPivot(username);
    }}

    async function runWinrmPth(account) {{
      if (!API_MODE || !account || opRunning) return;
      const pth = (OPS.pth_sessions || []).find(
        p => p.account.toLowerCase() === account.toLowerCase()
      );
      if (!pth) {{
        showUiToast('Sin hash para ' + account + ' — ejecuta exploit gMSA');
        return;
      }}
      const ok = await postOp('/api/winrm', {{ account: pth.account }}, 'WINRM PTH ' + pth.account);
      if (ok) showUiToast('WinRM PTH en curso — revisa terminal', true);
    }}

    function showScreen(name) {{
      screen = name;
      document.querySelectorAll('.screen').forEach(s => s.classList.remove('active'));
      $('screen-' + name).classList.add('active');
      if (name === 'hq') {{
        initHQRoom();
        if (!hqAnimId) hqAnimId = requestAnimationFrame(hqLoop);
      }}
      if (name === 'play') {{
        requestAnimationFrame(() => initGraph());
        connectEvents();
      }}
    }}

    function activePhase() {{
      return (OPS.phases || []).find(p => p.status === 'active') || null;
    }}

    function termLine(text, cls) {{
      const t = $('terminal');
      const cursor = t.querySelector('.cursor');
      const span = document.createElement('div');
      if (cls) span.className = cls;
      span.textContent = text;
      t.insertBefore(span, cursor);
      t.scrollTop = t.scrollHeight;
    }}

  function typeLine(text, cls, cb) {{
      let i = 0;
      const t = $('terminal');
      const cursor = t.querySelector('.cursor');
      const span = document.createElement('div');
      if (cls) span.className = cls;
      t.insertBefore(span, cursor);
      function tick() {{
        if (i < text.length) {{
          span.textContent += text[i++];
          t.scrollTop = t.scrollHeight;
          setTimeout(tick, 8 + Math.random() * 12);
        }} else if (cb) cb();
      }}
      tick();
    }}

    function setOpState(running) {{
      opRunning = running;
      $('op-status').textContent = running ? 'RUNNING' : 'IDLE';
      $('progress-bar').classList.toggle('active', running);
      $('scan-overlay').classList.toggle('active', running);
      document.querySelectorAll('.action-btn, .mission-btn').forEach(btn => {{
        btn.disabled = running;
        btn.classList.toggle('running', running);
      }});
    }}

    function flash(kind) {{
      document.body.classList.remove('flash-success', 'flash-error');
      void document.body.offsetWidth;
      document.body.classList.add(kind === 'ok' ? 'flash-success' : 'flash-error');
    }}

    async function fetchState() {{
      if (!API_MODE) return;
      try {{
        const r = await fetch('/api/state');
        if (r.ok) OPS = await r.json();
      }} catch (e) {{ /* offline */ }}
    }}

    function renderPhases() {{
      const fb = $('framework-bar');
      if (fb) fb.textContent = OPS.engagement_framework || '';
      const el = $('phases');
      el.innerHTML = (OPS.phases || []).map(p => {{
        const fw = p.framework || {{}};
        const refs = [fw.crtp, (fw.mitre || []).join('/')].filter(Boolean).join(' · ');
        const tip = [p.detail, fw.crtp, fw.crte, fw.crto, (fw.mitre || []).join(', ')].filter(Boolean).join('\\n');
        return `<div class="phase ${{p.status}}" data-id="${{p.id}}" title="${{tip}}">
          <div class="code">${{p.code}}</div>
          <div class="title">${{p.title}}</div>
          <div class="ref">${{refs}}</div>
        </div>`;
      }}).join('');
    }}

    function bootLine(text, cls) {{
      const t = $('boot-terminal');
      if (!t) return;
      const div = document.createElement('div');
      if (cls) div.className = cls;
      div.textContent = text;
      t.appendChild(div);
      t.scrollTop = t.scrollHeight;
    }}

    function initBoot() {{
      const t = $('boot-terminal');
      if (!t) return;
      t.innerHTML = '';
      bootLine('AD Ops v1 — modo BLACKBOX');
      bootLine('Sin dominio. Sin credenciales. Sin mapa.');
      bootLine('');
      bootLine('Introduce la IP del objetivo y pulsa Enter.');
      bootLine('Se ejecutará: admapper scan -H <IP>');
      bootLine('');
      const m = OPS.meta || {{}};
      const tip = m.target_ip || m.dc_ip;
      if (tip) {{
        bootLine('IP configurada: ' + tip + ' — Enter para escanear', 'line-phase');
        $('boot-ip').value = tip;
      }}
    }}

    function isValidIp(s) {{
      return /^(?:\\d{{1,3}}\\.){{3}}\\d{{1,3}}$/.test(s.trim());
    }}

    async function submitBootIp() {{
      const ip = ($('boot-ip') || {{}}).value.trim();
      if (!isValidIp(ip)) {{
        bootLine('IP inválida — formato 10.x.x.x', 'line-error');
        return;
      }}
      if (!API_MODE) {{
        bootLine('Inicia el servidor: admapper dashboard -H ' + ip, 'line-error');
        return;
      }}
      bootLine('> scan -H ' + ip, 'line-cmd');
      bootLine('Enumerando Kerberos, LDAP, SMB…');
      try {{
        const r = await fetch('/api/scan', {{
          method: 'POST',
          headers: {{ 'Content-Type': 'application/json' }},
          body: JSON.stringify({{ ip }}),
        }});
        if (!r.ok) {{
          bootLine('error HTTP ' + r.status, 'line-error');
          return;
        }}
        setOpState(true);
        connectEvents();
        const poll = setInterval(async () => {{
          if (opRunning) return;
          clearInterval(poll);
          await fetchState();
          if ((OPS.topology || {{}}).has_scan) {{
            bootLine('Recon completo — desplegando mapa…', 'line-phase');
            setTimeout(() => enterHQ(), 600);
          }}
        }}, 800);
      }} catch (e) {{
        bootLine('error: ' + e, 'line-error');
      }}
    }}

    function hqFill(ctx, x, y, w, h, c) {{
      if (!c) return;
      ctx.fillStyle = c;
      ctx.fillRect(x, y, w, h);
    }}

    function hqTile(ctx, tx, ty, c) {{
      hqFill(ctx, tx * HQ.TILE, ty * HQ.TILE, HQ.TILE, HQ.TILE, c);
    }}

    function hqSprite(ctx, rows, ox, oy, flip) {{
      const pal = HQ_PAL;
      for (let y = 0; y < rows.length; y++) {{
        const row = rows[y];
        for (let x = 0; x < row.length; x++) {{
          const ch = row[flip ? row.length - 1 - x : x];
          const c = pal[ch];
          if (c) hqFill(ctx, ox + x, oy + y, 1, 1, c);
        }}
      }}
    }}

    function hqDrawSprite(ctx, art, tx, ty) {{
      const flip = art.flip;
      const ox = Math.round(tx * HQ.TILE - 8);
      const oy = Math.round(ty * HQ.TILE - 15);
      hqSprite(ctx, art.rows, ox, oy, flip);
    }}

    const HQ_SPRITES = {{
      down: [
        ['....BBBB....','...BHHHB...','..BHHHHB..','.BPPPPPB.','.BPPPPPB.','BSHSHSHSB','BSHSHSHSB','.BSSSSSB.','..BBBBB..','...K.K...','...K.K...','....B....'],
        ['....BBBB....','...BHHHB...','..BHHHHB..','.BPPPPPB.','.BPPPPPB.','BSHSHSHSB','BSHSHSHSB','.BSSSSSB.','..BBBBB..','..K...K..','.K.....K.','....B....'],
      ],
      up: [
        ['....BBBB....','...BHHHB...','..BHHHHB..','.BSHSHSB.','BSHHHHHSB','BSSSSSSSB','BSSSSSSSB','.BSSSSSB.','..BBBBB..','...K.K...','...K.K...','....B....'],
        ['....BBBB....','...BHHHB...','..BHHHHB..','.BSHSHSB.','BSHHHHHSB','BSSSSSSSB','BSSSSSSSB','.BSSSSSB.','..BBBBB..','..K...K..','.K.....K.','....B....'],
      ],
      left: [
        ['....BBBB....','...BHHHB...','..BHHHB...','.BPPPPB...','BPPPPPB...','BSHSHHSB..','BSHSHHSB..','.BSSSB....','..BBBB....','...K.K....','...K.K....','....B....'],
        ['....BBBB....','...BHHHB...','..BHHHB...','.BPPPPB...','BPPPPPB...','BSHSHHSB..','BSHSHHSB..','.BSSSB....','..BBBB....','..K...K...','.K.....K..','....B....'],
      ],
    }};

    function hqPlayerArt() {{
      const d = hqPlayer.dir === 'right' ? 'left' : hqPlayer.dir;
      const frames = HQ_SPRITES[d] || HQ_SPRITES.down;
      const fi = hqPlayer.moving ? hqPlayer.frame % 2 : 0;
      return {{ rows: frames[fi], flip: hqPlayer.dir === 'right' }};
    }}

    function hqDrawFloor(ctx) {{
      const T = HQ.TILE;
      for (let ty = 4; ty < HQ.ROWS; ty++) {{
        for (let tx = 0; tx < HQ.COLS; tx++) {{
          const rug = tx >= 1 && tx <= 9 && ty >= 7 && ty <= 12;
          if (rug) {{
            hqTile(ctx, tx, ty, ((tx + ty) % 2) ? HQ_PAL.R1 : HQ_PAL.R2);
            if (tx === 1 || tx === 9 || ty === 7 || ty === 12) {{
              hqFill(ctx, tx * T, ty * T, T, 2, HQ_PAL.RF);
            }}
          }} else {{
            const plank = ((tx + Math.floor(ty / 2)) % 2) ? HQ_PAL.F1 : HQ_PAL.F2;
            hqTile(ctx, tx, ty, plank);
            hqFill(ctx, tx * T, ty * T + T - 2, T, 1, HQ_PAL.F3);
          }}
        }}
      }}
      for (let tx = 0; tx < HQ.COLS; tx++) {{
        hqTile(ctx, tx, 3, HQ_PAL.BB);
        hqFill(ctx, tx * T, 3 * T + T - 3, T, 2, HQ_PAL.B);
      }}
    }}

    function hqDrawWalls(ctx) {{
      const T = HQ.TILE;
      for (let ty = 0; ty < 3; ty++) {{
        for (let tx = 0; tx < HQ.COLS; tx++) {{
          hqTile(ctx, tx, ty, ty === 0 ? HQ_PAL.W : HQ_PAL.W2);
          if (ty === 1) hqFill(ctx, tx * T, ty * T + 6, T, 1, HQ_PAL.WL);
        }}
      }}
      const win = (wx) => {{
        hqFill(ctx, wx * T, 2 * T, 2 * T, T, HQ_PAL.RD);
        hqFill(ctx, wx * T + 3, 2 * T + 3, 2 * T - 6, T - 6, HQ_PAL.L);
        hqFill(ctx, wx * T + 5, 2 * T + 5, 4, 4, HQ_PAL.WH);
      }};
      win(2);
      win(6);
      hqFill(ctx, 16 * T, 2 * T, 3 * T, 3 * T, HQ_PAL.BD);
      for (let i = 0; i < 3; i++) hqFill(ctx, (16 + i) * T + 3, 4 * T, T - 6, 5, HQ_PAL.F3);
      hqFill(ctx, 1 * T, 1 * T, 6 * T, T, HQ_PAL.B);
      hqFill(ctx, 2 * T, 1 * T + 5, 4 * T, 5, HQ_PAL.T);
    }}

    function hqDrawDeskBack(ctx) {{
      const T = HQ.TILE;
      hqFill(ctx, 1 * T, 4 * T, 7 * T, T, HQ_PAL.D1);
      hqFill(ctx, 1 * T, 4 * T, 7 * T, 2, HQ_PAL.B);
      hqFill(ctx, 1 * T + 2, 4 * T + T - 4, 7 * T - 4, 2, HQ_PAL.D2);
      hqFill(ctx, 2 * T + 4, 2 * T + 4, 2 * T - 8, T - 2, HQ_PAL.M);
      hqFill(ctx, 2 * T + 6, 2 * T + 6, 2 * T - 12, T - 8, HQ_PAL.S);
      hqFill(ctx, 2 * T + 8, 2 * T + 10, 10, 5, HQ_PAL.T);
      hqFill(ctx, 2 * T + 6, 3 * T - 3, 2 * T - 12, 3, HQ_PAL.B);
      hqFill(ctx, 2 * T + 2, 4 * T + 5, 4 * T - 4, 5, HQ_PAL.K);
      for (let i = 0; i < 8; i++) hqFill(ctx, 2 * T + 4 + i * 5, 4 * T + 7, 3, 2, HQ_PAL.WL);
      hqFill(ctx, 6 * T + 3, 3 * T + 2, T - 6, 2 * T + 2, HQ_PAL.K);
      hqFill(ctx, 6 * T + 5, 3 * T + 4, 4, 4, HQ_PAL.G2);
    }}

    function hqDrawDeskFront(ctx) {{
      const T = HQ.TILE;
      hqFill(ctx, 1 * T, 5 * T + 6, 7 * T, 8, HQ_PAL.D2);
      hqFill(ctx, 1 * T, 5 * T + 6, 7 * T, 2, HQ_PAL.B);
    }}

    function hqDrawStool(ctx) {{
      const T = HQ.TILE;
      hqFill(ctx, 3 * T + 1, 7 * T + 1, T + 6, T - 2, HQ_PAL.C);
      hqFill(ctx, 3 * T + 1, 7 * T + 1, T + 6, 3, HQ_PAL.B);
      hqFill(ctx, 3 * T + 4, 7 * T + T - 5, T, 4, HQ_PAL.B);
    }}

    function hqDrawDresser(ctx) {{
      const T = HQ.TILE;
      hqFill(ctx, 10 * T, 4 * T, 2 * T, 2 * T, HQ_PAL.DR);
      hqFill(ctx, 10 * T, 4 * T, 2 * T, 3, HQ_PAL.B);
      hqFill(ctx, 10 * T + 3, 4 * T + 6, 2 * T - 6, 4, HQ_PAL.DR2);
      hqFill(ctx, 10 * T + 3, 5 * T + 2, 2 * T - 6, 4, HQ_PAL.DR2);
      hqFill(ctx, 10 * T + 5, 4 * T + 8, 4, 4, HQ_PAL.K);
      hqFill(ctx, 10 * T + T - 6, 4 * T + 8, 4, 4, HQ_PAL.K);
    }}

    function hqDrawShelf(ctx) {{
      const T = HQ.TILE;
      hqFill(ctx, 12 * T, 4 * T, 3 * T, 2 * T, HQ_PAL.G);
      hqFill(ctx, 12 * T, 4 * T, 3 * T, 3, HQ_PAL.B);
      hqFill(ctx, 12 * T, 5 * T - 1, 3 * T, 2, HQ_PAL.G2);
      hqFill(ctx, 12 * T + 3, 4 * T + 3, 8, 10, HQ_PAL.PU);
      hqFill(ctx, 12 * T + 14, 4 * T + 3, 6, 6, HQ_PAL.C);
      hqFill(ctx, 13 * T + 2, 4 * T + 5, 3, 8, HQ_PAL.Y);
      hqFill(ctx, 14 * T + 2, 4 * T + 5, 3, 8, HQ_PAL.O);
    }}

    function hqDrawTv(ctx) {{
      const T = HQ.TILE;
      hqFill(ctx, 15 * T, 4 * T + 2, 3 * T, T + 6, HQ_PAL.K);
      hqFill(ctx, 15 * T + 4, 4 * T + 5, 3 * T - 8, T - 2, HQ_PAL.M);
      hqFill(ctx, 15 * T, 5 * T + 8, 3 * T, 5, HQ_PAL.BD);
      const gc = [HQ_PAL.PU, HQ_PAL.O, HQ_PAL.G, HQ_PAL.C, HQ_PAL.Y];
      for (let i = 0; i < 5; i++) {{
        hqFill(ctx, (15 * T + 2 + i * 9), 5 * T + 10, 7, 10, gc[i]);
      }}
      hqFill(ctx, 17 * T + 6, 4 * T + 10, 4, 8, HQ_PAL.WH);
    }}

    function hqDrawBed(ctx) {{
      const T = HQ.TILE;
      hqFill(ctx, 14 * T, 9 * T, 5 * T, 4 * T, HQ_PAL.BD);
      hqFill(ctx, 14 * T, 9 * T, 5 * T, 3, HQ_PAL.B);
      hqFill(ctx, 14 * T + 2, 9 * T + 2, 4 * T - 4, T - 2, HQ_PAL.BK);
      hqFill(ctx, 17 * T + 4, 9 * T + 2, T - 6, 8, HQ_PAL.BK);
      for (let row = 0; row < 3; row++) {{
        const c = row % 2 ? HQ_PAL.PV : HQ_PAL.PV2;
        hqFill(ctx, 14 * T + 2, (11 + row) * T, 4 * T - 4, T, c);
      }}
    }}

    function hqDrawPlayerShadow(ctx, tx, ty) {{
      const cx = Math.round(tx * HQ.TILE);
      const cy = Math.round(ty * HQ.TILE + 1);
      ctx.globalAlpha = 0.28;
      hqFill(ctx, cx - 7, cy, 14, 5, HQ_PAL.B);
      ctx.globalAlpha = 1;
    }}

    function hqDrawLaptopGlow(ctx, active) {{
      if (!active) return;
      const T = HQ.TILE;
      const x = 2 * T + 4;
      const y = 2 * T + 4;
      ctx.globalAlpha = 0.28 + 0.18 * Math.sin(Date.now() / 200);
      hqFill(ctx, x - 3, y - 3, 2 * T + 2, T + 2, HQ_PAL.T);
      ctx.globalAlpha = 1;
    }}

    function hqBuildStatic() {{
      const c = document.createElement('canvas');
      c.width = HQ.W;
      c.height = HQ.H;
      const ctx = c.getContext('2d');
      ctx.imageSmoothingEnabled = false;
      hqDrawWalls(ctx);
      hqDrawFloor(ctx);
      hqDrawBed(ctx);
      hqDrawDresser(ctx);
      hqDrawShelf(ctx);
      hqDrawTv(ctx);
      hqDrawDeskBack(ctx);
      return c;
    }}

    function hqFeetY() {{ return hqPlayer.ty; }}

    function hqRender() {{
      if (!hqCtx || !hqCanvas) return;
      const ctx = hqCtx;
      const sc = HQ.SCALE;
      ctx.save();
      ctx.setTransform(sc, 0, 0, sc, 0, 0);
      ctx.imageSmoothingEnabled = false;
      ctx.clearRect(0, 0, HQ.W, HQ.H);
      if (hqStatic) ctx.drawImage(hqStatic, 0, 0);
      const z = hqFeetY();
      const layers = [
        {{ y: 7.0, draw: () => hqDrawStool(ctx) }},
        {{ y: 5.35, draw: () => hqDrawDeskFront(ctx) }},
        {{ y: z - 0.01, draw: () => hqDrawPlayerShadow(ctx, hqPlayer.tx, hqPlayer.ty) }},
        {{ y: z, draw: () => hqDrawSprite(ctx, hqPlayerArt(), hqPlayer.tx, hqPlayer.ty) }},
      ];
      layers.sort((a, b) => a.y - b.y);
      layers.forEach(l => l.draw());
      const near = hqNearestInteractable();
      hqDrawLaptopGlow(ctx, near && near.id === 'laptop');
      ctx.restore();
      const prompt = $('hq-prompt');
      hqNearId = near ? near.id : null;
      if (prompt) {{
        if (near) {{
          prompt.textContent = '[E] ' + near.label;
          prompt.classList.add('active');
        }} else {{
          prompt.textContent = '';
          prompt.classList.remove('active');
        }}
      }}
    }}

    function hqBlocked(tx, ty) {{
      const pts = [[tx - 0.28, ty + 0.05], [tx + 0.28, ty + 0.05], [tx - 0.28, ty + 0.42], [tx + 0.28, ty + 0.42]];
      for (const [px, py] of pts) {{
        const gx = Math.floor(px);
        const gy = Math.floor(py);
        if (gx < 1 || gy < 3 || gx >= HQ.COLS - 1 || gy >= HQ.ROWS) return true;
        if (HQ.collision[gy][gx]) return true;
      }}
      return false;
    }}

    function hqNearestInteractable() {{
      let best = null;
      let bestD = Infinity;
      for (const it of HQ.interactables) {{
        const d = Math.hypot(hqPlayer.tx - it.tx, hqPlayer.ty - it.ty);
        if (d > it.r || d >= bestD) continue;
        if (it.face && hqPlayer.dir !== it.face) continue;
        best = it;
        bestD = d;
      }}
      return best;
    }}

    function initHQRoom(opts) {{
      opts = opts || {{}};
      if (!hqBuilt) {{
        hqCanvas = $('hq-canvas');
        if (hqCanvas) {{
          hqCanvas.width = HQ.W * HQ.SCALE;
          hqCanvas.height = HQ.H * HQ.SCALE;
          hqCtx = hqCanvas.getContext('2d');
        }}
        hqStatic = hqBuildStatic();
        hqBuilt = true;
        const dlgNo = $('hq-dialog-no');
        const dlgYes = $('hq-dialog-yes');
        if (dlgNo) dlgNo.onclick = () => $('hq-dialog').classList.add('hidden');
        if (dlgYes) dlgYes.onclick = () => hqBeginDeskSession();
        hqResetDialog();
      }}
      if (!opts.preserve) {{
        const hasSession = (OPS.topology || {{}}).has_scan || (OPS.meta || {{}}).blackbox === false;
        const sp = hasSession ? HQ.spawnDesk : HQ.spawnDefault;
        hqPlayer.tx = sp.tx;
        hqPlayer.ty = sp.ty;
        hqPlayer.dir = hasSession ? 'up' : 'down';
      }}
      $('hq-dialog')?.classList.add('hidden');
      hqRender();
    }}

    function hqLoop(ts) {{
      hqAnimId = requestAnimationFrame(hqLoop);
      if (screen !== 'hq') return;
      const dt = Math.min(0.05, (hqLoop._last ? ts - hqLoop._last : 16) / 1000);
      hqLoop._last = ts;
      let dx = 0;
      let dy = 0;
      if (hqKeys['ArrowUp'] || hqKeys['w'] || hqKeys['W']) dy -= 1;
      if (hqKeys['ArrowDown'] || hqKeys['s'] || hqKeys['S']) dy += 1;
      if (hqKeys['ArrowLeft'] || hqKeys['a'] || hqKeys['A']) dx -= 1;
      if (hqKeys['ArrowRight'] || hqKeys['d'] || hqKeys['D']) dx += 1;
      const len = Math.hypot(dx, dy);
      if (len > 0) {{
        dx /= len;
        dy /= len;
        const speed = 3.2;
        const nx = hqPlayer.tx + dx * speed * dt;
        const ny = hqPlayer.ty + dy * speed * dt;
        if (!hqBlocked(nx, hqPlayer.ty)) hqPlayer.tx = nx;
        if (!hqBlocked(hqPlayer.tx, ny)) hqPlayer.ty = ny;
        hqPlayer.moving = true;
        hqWalkTick += dt;
        if (hqWalkTick > 0.12) {{ hqWalkTick = 0; hqPlayer.frame = (hqPlayer.frame + 1) % 2; }}
        if (Math.abs(dx) >= Math.abs(dy)) hqPlayer.dir = dx < 0 ? 'left' : 'right';
        else hqPlayer.dir = dy < 0 ? 'up' : 'down';
      }} else {{
        hqPlayer.moving = false;
        hqPlayer.frame = 0;
      }}
      hqRender();
    }}

    function hqResetDialog() {{
      const yes = $('hq-dialog-yes');
      if (yes) {{
        yes.textContent = 'Sí — sentarse';
        yes.onclick = () => hqBeginDeskSession();
      }}
    }}

    function hqBeginDeskSession() {{
      $('hq-dialog')?.classList.add('hidden');
      const fade = $('hq-fade');
      const target = {{ tx: HQ.spawnDesk.tx, ty: HQ.spawnDesk.ty - 0.1 }};
      hqPlayer.dir = 'up';
      hqPlayer.moving = true;
      let start = null;
      const step = (ts) => {{
        if (!start) start = ts;
        const t = Math.min(1, (ts - start) / 380);
        hqPlayer.tx += (target.tx - hqPlayer.tx) * 0.22;
        hqPlayer.ty += (target.ty - hqPlayer.ty) * 0.22;
        hqPlayer.frame = Math.floor(t * 4) % 2;
        hqRender();
        if (t < 1) requestAnimationFrame(step);
        else {{
          hqPlayer.moving = false;
          hqPlayer.tx = target.tx;
          hqPlayer.ty = target.ty;
          hqRender();
          if (fade) fade.classList.add('active');
          setTimeout(() => {{
            if (fade) fade.classList.remove('active');
            enterPlay();
          }}, 520);
        }}
      }};
      requestAnimationFrame(step);
    }}

    function hqInteract() {{
      const near = hqNearestInteractable();
      if (!near) return;
      hqResetDialog();
      const dlg = $('hq-dialog');
      const txt = $('hq-dialog-text');
      if (near.id === 'laptop') {{
        if (txt) txt.textContent = '¿Abrir AD OPS en la laptop?';
        if (dlg) dlg.classList.remove('hidden');
        return;
      }}
      if (txt) txt.textContent = near.flavor || '…';
      const yes = $('hq-dialog-yes');
      if (yes) {{
        yes.textContent = 'OK';
        yes.onclick = () => dlg.classList.add('hidden');
      }}
      if (dlg) dlg.classList.remove('hidden');
    }}

    function enterHQ(preservePos) {{
      const keep = preservePos === true || screen === 'play';
      initHQRoom({{ preserve: keep }});
      showScreen('hq');
    }}

    function hqCloseUi() {{
      $('hq-dialog')?.classList.add('hidden');
      $('hq-fade')?.classList.remove('active');
    }}

    function enterPlay() {{
      hqCloseUi();
      renderAll();
      showScreen('play');
      termLine('workspace ' + ((OPS.meta || {{}}).workspace || ''));
      const scanned = (OPS.topology || {{}}).has_scan;
      termLine(scanned
        ? 'Mapa NETWORK activo — clic en DC para servicios; AD MAP tras enum'
        : 'Sin escaneo en esta partida — ▶ ESCANEAR o autentica con IP conocida');
    }}

    function renderHudMeta() {{
      const m = OPS.meta || {{}};
      const dom = m.domain_known ? m.domain : '???';
      const dc = m.dc_ip || '—';
      const host = m.dc_host || '';
      $('hud-meta').innerHTML =
        `<div><strong>${{m.workspace}}</strong> · dominio <strong>${{dom}}</strong></div>` +
        `<div>target ${{dc}} ${{host}}</div>`;
    }}

    function opsProgress() {{
      return OPS.progress || {{
        scan: true, enum_users: true, loot: true, acls: true, exploit: true,
      }};
    }}

    function phaseToReadiness(phase) {{
      if (!phase) return 'recon';
      const map = {{
        g02: 'recon', g03: 'enum', g04: 'creds', g05: 'creds',
        g06: 'enum', g07: 'escalate', g08: 'escalate', g09: 'escalate',
      }};
      return map[phase.id] || 'recon';
    }}

    function filterAttackVectors(vectors) {{
      const lens = getDisplayLens();
      if (!isInspectingOther() || !lens.username) return vectors;
      const vu = graphFocus.toLowerCase();
      const flags = lens.enum_flags || [];
      return vectors.filter(v => {{
        if (['recon', 'enum'].includes(v.phase)) return true;
        const aid = (v.attack_id || '').toLowerCase();
        const targets = v.targets || [];
        const hit = t => (t.username || '').toLowerCase() === vu;
        if (flags.includes('asrep') && aid.includes('asrep')) return targets.some(hit);
        if (flags.includes('kerberoast') && aid.includes('kerberoast')) return targets.some(hit);
        return false;
      }});
    }}

    function activeGraphData() {{
      if (viewMode === 'ad') return OPS.graph || {{ nodes: [], edges: [] }};
      return OPS.topology || OPS.graph || {{ nodes: [], edges: [] }};
    }}

    function currentMission() {{
      const quests = OPS.quests || [];
      if (selectedMissionId) {{
        const picked = quests.find(q => q.id === selectedMissionId);
        if (picked) return picked;
      }}
      return OPS.mission || null;
    }}

    function renderLeft() {{
      const p = OPS.player || {{}};
      const g = OPS.ops || {{}};
      let html = '';

      if (viewMode === 'network') {{
        html += `<div class="objective"><p class="sub"><strong>Mapa NETWORK</strong> — solo infra descubierta (scan + enum). Sin ACLs ni usuarios; cambia a <strong>AD MAP</strong> tras enum autenticada.</p></div>`;
      }}

      html += `<div class="objective"><h2>OPERADOR</h2>`;
      html += `<p class="sub">Pivot: <strong>${{p.pivot || '—'}}</strong>`;
      if ((p.owned || []).length) html += ` · owned: ${{(p.owned || []).join(', ')}}`;
      html += '</p>';
      html += `<p class="sub"><strong>${{g.stage_label || '—'}}</strong></p></div>`;

      const actions = getDisplayActions();
      if (actions.length) {{
        html += '<h3>Acciones</h3>';
        actions.forEach((a, i) => {{
          const req = a.required ? ' *' : '';
          const cls = i === 0 ? 'action-btn mission-btn' : 'action-btn';
          html += `<button class="${{cls}}" data-aid="${{a.id}}" data-action="${{a.action}}">${{a.button}}${{req}}</button>`;
          if (a.reason) html += `<p class="hl">${{a.reason}}</p>`;
        }});
      }} else {{
        html += '<p class="hl">Nada habilitado — completa el paso anterior (ver NOTAS →)</p>';
      }}

      if (g.stage === 'need_creds' && g.engagement_over) {{
        html += `<p class="hl" style="color:var(--danger)">${{g.engagement_over_message || 'No credentials available. Add a valid credential to continue the engagement.'}}</p>`;
      }}

      const lens = getDisplayLens();
      const pivotNow = activePivot();
      const focusNow = graphFocus ? graphFocus.toLowerCase() : '';
      if (lens.username) {{
        const readOnly = lens.read_only || isInspectingOther();
        const isPivotLens = lens.username.toLowerCase() === pivotNow;
        html += `<div class="objective"><h2>PERFIL · ${{lens.username}}${{readOnly && !isPivotLens ? ' (inspección)' : (isPivotLens ? ' (pivot)' : '')}}</h2>`;
        html += `<p class="sub">${{lens.status_label || ''}}</p>`;
        if (lens.inventory && lens.inventory.dn) html += `<p class="sub mono">${{lens.inventory.dn}}</p>`;
        if (readOnly) {{
          html += '<p class="hl" style="color:var(--warn)">Sin credencial — no es pivot operativo</p>';
        }}
        if (lens.access_matrix) {{
          const r = lens.access_matrix;
          html += `<p class="sub">ldap ${{r[1]}} · smb ${{r[2]}} · krb ${{r[3]}} · winrm ${{r[4]}}</p>`;
        }}
        if (lens.is_machine && lens.winrm_cmd) {{
          html += `<p class="sub mono">${{lens.winrm_cmd}}</p>`;
        }}
        if (graphFocus && focusNow !== pivotNow) {{
          html += `<button type="button" class="action-btn" id="btn-operar-como">▶ OPERAR COMO ${{graphFocus}}</button>`;
          html += `<button type="button" class="action-btn secondary" id="btn-volver-pivot">← Volver al pivot (${{p.pivot || '—'}})</button>`;
        }} else if (graphFocus && focusNow === pivotNow) {{
          html += `<button type="button" class="action-btn secondary" id="btn-clear-focus">← Deseleccionar nodo</button>`;
        }}
        html += '</div>';
      }}

      const identities = OPS.selectable_identities || [];
      if (identities.length) {{
        html += '<h3>Identidades</h3><p class="sub">Clic = inspeccionar · Operar como = pivot (naranja)</p><p>';
        identities.forEach(id => {{
          const ul = id.username.toLowerCase();
          let active = '';
          if (ul === pivotNow) active = ' pivot-active';
          if (focusNow && ul === focusNow && ul !== pivotNow) active = ' focus-active';
          html += `<button type="button" class="chip pivot-btn${{active}}" data-focus="${{id.username}}" title="${{id.detail || id.role || ''}}">${{id.username}}</button> `;
        }});
        html += '</p>';
      }}

      const creds = OPS.creds || [];
      const pthSessions = OPS.pth_sessions || [];
      if (creds.length) {{
        html += '<h3>Credenciales (password)</h3><ul class="list">';
        creds.forEach(c => {{
          const cls = c.status === 'valid' ? 'valid' : '';
          html += `<li><button type="button" class="chip pivot-btn ${{cls}}" data-cred-user="${{c.user}}">${{c.user}}</button> <span class="chip">${{c.status}}</span></li>`;
        }});
        html += '</ul>';
      }}
      if (pthSessions.length) {{
        html += '<div class="objective"><h2>WinRM PTH (hash)</h2>';
        html += '<p class="sub">Cuenta gMSA/máquina — sin password LDAP. Conecta shell como evil-winrm.</p>';
        pthSessions.forEach(p => {{
          html += `<p class="sub"><strong>${{p.account}}</strong> <span class="mono">${{p.nthash}}</span></p>`;
          html += `<button type="button" class="action-btn btn-pth-pivot" data-pth-user="${{p.account}}" style="margin:0.35rem 0">▶ CONECTAR WINRM PTH (${{p.account}})</button>`;
        }});
        html += '</div>';
      }}

      html += `<div class="cred-form">
        <label>Autenticar (usuario humano + password)</label>
        <input id="cred-user" placeholder="usuario (ej. svc_recovery)" autocomplete="off"/>
        <input id="cred-pass" type="password" placeholder="contraseña" autocomplete="off"/>
        <button type="button" class="action-btn" id="cred-submit" style="margin-top:0.5rem">▶ AUTENTICAR</button>
      </div>
      <div class="cred-form">
        <label>Password spray</label>
        <input id="spray-pass" type="password" placeholder="contraseña para spray" autocomplete="off"/>
      </div>`;

      $('left').innerHTML = html;

      document.querySelectorAll('[data-aid]').forEach(btn => {{
        btn.onclick = () => {{
          const act = (OPS.actions || []).find(a => a.id === btn.dataset.aid);
          if (act) runAction(act);
        }};
      }});
      document.querySelectorAll('[data-focus]').forEach(btn => {{
        btn.onclick = () => focusIdentity(btn.dataset.focus);
      }});
      const btnOperar = $('btn-operar-como');
      if (btnOperar) btnOperar.onclick = () => operarComo(graphFocus);
      const btnVolver = $('btn-volver-pivot');
      if (btnVolver) btnVolver.onclick = () => clearGraphFocus();
      const btnClear = $('btn-clear-focus');
      if (btnClear) btnClear.onclick = () => clearGraphFocus();
      document.querySelectorAll('[data-cred-user]').forEach(btn => {{
        btn.onclick = () => {{
          const el = $('cred-user');
          if (el) el.value = btn.dataset.credUser || '';
        }};
      }});
      const credSubmit = $('cred-submit');
      if (credSubmit) {{
        credSubmit.onclick = () => runAction({{ action: 'run', button: 'AUTENTICAR' }});
      }}
      document.querySelectorAll('.btn-pth-pivot').forEach(btn => {{
        btn.onclick = () => runWinrmPth(btn.dataset.pthUser || '');
      }});
    }}

    function parseUsernameFromNode(node) {{
      if (!node) return '';
      if (node.username) return node.username;
      const id = String(node.id || '');
      if (id.startsWith('user:') && id.includes('@')) {{
        return id.split(':')[1].split('@')[0];
      }}
      const label = String(node.label || '').replace(/^★\\s*/, '').split('\\n')[0].trim();
      if (label.startsWith('YOU') || label.startsWith('???')) return '';
      return label;
    }}

    function isInfraNode(node) {{
      if (!node) return true;
      const id = String(node.id || '');
      const group = String(node.group || '');
      if (id.startsWith('user:') || group === 'user') return false;
      return id === 'operator' || id === 'unknown' || id === 'domain'
        || group === 'host' || group === 'dc' || group === 'domain' || group === 'service'
        || id.startsWith('host:') || id.startsWith('svc:') || id.startsWith('computer:')
        || id.startsWith('gmsa:');
    }}

    function showTargetFromNode(node) {{
      if (!node) return;
      graphFocus = null;
      infraFocus = node;
      renderRight();
    }}

    function selectIdentityFromNode(node) {{
      if (!node) return;
      if (isInfraNode(node)) {{
        if (viewMode === 'network') showTargetFromNode(node);
        return;
      }}
      const user = parseUsernameFromNode(node);
      if (!user) return;
      focusIdentity(user);
    }}

    function contrastText(hexColor) {{
      const raw = String(hexColor || '').replace('#', '');
      if (raw.length !== 6) return '#f8fafc';
      const r = parseInt(raw.slice(0, 2), 16);
      const g = parseInt(raw.slice(2, 4), 16);
      const b = parseInt(raw.slice(4, 6), 16);
      const lum = (0.299 * r + 0.587 * g + 0.114 * b) / 255;
      return lum > 0.52 ? '#0f172a' : '#f8fafc';
    }}

    function nodeFontForColor(hexColor, prev) {{
      const fg = contrastText(hexColor);
      const stroke = fg === '#f8fafc' ? '#080b10' : '#f8fafc';
      return {{
        ...(prev || {{}}),
        color: fg,
        strokeWidth: 3,
        strokeColor: stroke,
        size: (prev && prev.size) || 11,
        face: 'IBM Plex Sans, sans-serif',
        align: 'center',
      }};
    }}

    function highlightIdentityGraph() {{
      if (!nodeData || !edgeData) return;
      const pivot = activePivot();
      const focus = (graphFocus || (OPS.player || {{}}).pivot || '').toLowerCase();
      const domain = ((OPS.meta || {{}}).domain || '').toLowerCase();
      const pivotBase = pivot.replace(/\\$$/, '');
      const pivotId = pivot && domain ? ('user:' + pivot + '@' + domain) : '';
      const focusId = focus && domain ? ('user:' + focus + '@' + domain) : '';
      nodeData.get().forEach(n => {{
        const ul = (n.username || parseUsernameFromNode(n)).toLowerCase();
        const nl = String(n.label || '').toLowerCase();
        const isPivot = pivot && (
          n.id === pivotId || ul === pivot || ul === pivotBase
          || (pivot.endsWith('$') && String(n.group) === 'gmsa' && pivotBase in nl)
        );
        const isFocus = focus && (n.id === focusId || ul === focus || ul === focus.replace(/\\$$/, ''));
        const owned = (n.label || '').startsWith('★');
        let color = typeof n.color === 'string' ? n.color : '#64748b';
        if (owned && !isPivot && !isFocus) color = '#22c55e';
        let size = viewMode === 'network' ? 14 : 22;
        let border = 2;
        if (isPivot) {{ color = '#f97316'; size = 30; border = 4; }}
        else if (isFocus) {{ color = '#eab308'; size = 28; border = 3; }}
        nodeData.update({{
          id: n.id,
          size,
          borderWidth: border,
          color,
          font: nodeFontForColor(color, n.font),
        }});
      }});
      edgeData.get().forEach(e => {{
        const fromPivot = pivotId && e.from === pivotId;
        edgeData.update({{
          id: e.id,
          width: fromPivot ? 4 : 2,
          color: {{ color: fromPivot ? '#3dffcf' : '#4a5568' }},
        }});
      }});
    }}

    async function setPivot(username) {{
      if (!API_MODE || !username) return;
      try {{
        const r = await fetch('/api/pivot', {{
          method: 'POST',
          headers: {{ 'Content-Type': 'application/json' }},
          body: JSON.stringify({{ username }}),
        }});
        const data = await r.json().catch(() => ({{}}));
        if (!r.ok) {{
          showUiToast(data.error || ('error pivot HTTP ' + r.status));
          return;
        }}
        if (data.state) OPS = data.state;
        graphFocus = null;
        infraFocus = null;
        renderAll();
        showUiToast('Pivot activo → ' + username, true);
        flash('ok');
      }} catch (e) {{
        showUiToast('error: ' + e);
      }}
    }}

    function noteKv(key, val, cls) {{
      if (val == null || val === '' || val === '???' || val === '—') return '';
      const c = cls ? ` note-val ${{cls}}` : ' note-val';
      return `<div class="note-kv"><span class="note-key">${{key}}</span><span class="note-arr">→</span><span class="${{c.trim()}}">${{val}}</span></div>`;
    }}

    function noteKvIndent(key, val, cls) {{
      const line = noteKv(key, val, cls);
      return line ? line.replace('class="note-kv"', 'class="note-kv indent"') : '';
    }}

    function primaryTarget() {{
      const m = OPS.meta || {{}};
      const topo = OPS.topology || {{}};
      const targets = topo.targets || [];
      const dc = targets.find(t => t.is_dc) || targets[0] || {{}};
      return {{
        ip: m.dc_ip || dc.address || '???',
        hostname: (m.dc_host || dc.hostname || '').replace(/^desconocido$/i, ''),
        domain: m.domain_known ? (m.domain || '') : '',
        services: dc.services || [],
        role: dc.role || 'HOST',
      }};
    }}

    function formatPorts(services) {{
      if (!services || !services.length) return '';
      return services.map(s => s.label || (s.port ? `TCP/${{s.port}}` : '')).filter(Boolean).join(', ');
    }}

    function renderNotesHeader() {{
      const t = primaryTarget();
      const title = t.domain ? `# ${{t.ip}} — ${{t.domain}}` : `# ${{t.ip}}`;
      const sub = t.hostname ? `<div class="note-sub">${{t.hostname}}</div>` : '';
      return `<div class="note-header">${{title}}${{sub}}</div>`;
    }}

    function renderTargetBlock() {{
      const prog = opsProgress();
      const t = primaryTarget();
      if (!prog.scan && t.ip === '???') {{
        return noteKv('Target', 'sin escanear', 'dim') + noteKv('TODO', 'scan -H &lt;IP&gt;', 'warn');
      }}
      let html = '<div class="note-block-label">Target</div>';
      html += noteKv('Target', t.ip);
      if (t.hostname) html += noteKv('Hostname', t.hostname);
      if (t.domain) html += noteKv('Domain', t.domain);
      const ports = formatPorts(t.services);
      if (ports) html += noteKv('Ports', ports);
      if (t.role) html += noteKv('Role', t.role);
      const p = OPS.player || {{}};
      if (p.pivot) html += noteKv('Pivot', p.pivot, 'ok');
      const owned = (p.owned || []).filter(Boolean);
      if (owned.length) html += noteKv('Owned', owned.join(', '));
      const g = OPS.ops || {{}};
      if (g.stage_label) html += noteKv('Fase', g.stage_label, 'dim');
      return html;
    }}

    function renderInfraNote() {{
      return renderTargetBlock();
    }}

    function renderInfraFocusNote() {{
      if (!infraFocus || viewMode !== 'network') return '';
      const node = infraFocus;
      const targets = (OPS.topology || {{}}).targets || [];
      const match = targets.find(t => t.id === node.id);
      let html = '<div class="note-callout focus"><div class="note-block-label">Nodo seleccionado</div>';
      if (match) {{
        html += noteKv('Target', match.address);
        html += noteKv('Hostname', match.hostname !== 'desconocido' ? match.hostname : '');
        html += noteKv('Role', match.role);
        const ports = formatPorts(match.services);
        if (ports) html += noteKv('Ports', ports);
      }} else {{
        html += noteKv('Nodo', (node.title || node.label || node.id).replace(/\\n/g, ' · '));
      }}
      html += '<button type="button" class="action-btn secondary" id="btn-clear-infra" style="margin-top:0.45rem">✕ Cerrar</button></div>';
      return html;
    }}

    function renderPivotNote() {{
      if (!graphFocus) return '';
      const lens = lensForUser(graphFocus);
      if (!lens.username) return '';
      const readOnly = lens.read_only || isInspectingOther();
      let html = `<div class="note-callout focus"><div class="note-block-label">Focus</div>`;
      html += noteKv('Usuario', lens.username, readOnly ? 'warn' : 'ok');
      if (lens.status_label) html += noteKv('Estado', lens.status_label, 'dim');
      if ((lens.enum_flags || []).length) {{
        html += noteKv('Flags', lens.enum_flags.join(', '));
      }}
      const caps = (lens.capabilities || []).slice(0, 6);
      caps.forEach(c => {{
        const mark = c.verified ? '✓' : (c.graph_only ? '?' : '·');
        const tail = c.enabled ? '' : ` (${{c.blocked_reason || 'bloqueado'}})`;
        html += noteKvIndent(`${{mark}} ${{c.technique}}`, `${{c.target}}${{tail}}`);
      }});
      if (lens.loot_clue) {{
        html += noteKv('Pista', `«${{lens.loot_clue.string}}»`, 'warn');
      }}
      const blocked = (lens.missions || []).filter(m => !m.enabled);
      blocked.slice(0, 3).forEach(m => {{
        html += noteKvIndent('bloqueado', `${{m.technique}} → ${{m.target}}`, 'dim');
      }});
      if (readOnly) html += noteKv('Nota', 'solo lectura — usa Operar como', 'warn');
      html += '</div>';
      return html;
    }}

    function renderNextStepsNote(intel) {{
      let vectors = filterAttackVectors((intel || {{}}).attack_readiness || []);
      if (!vectors.length) return '';
      const phaseOrder = ['recon', 'creds', 'enum', 'loot', 'escalate'];
      const readinessPhase = phaseToReadiness(activePhase());
      const sorted = [...vectors].sort((a, b) => {{
        const ia = phaseOrder.indexOf(a.phase);
        const ib = phaseOrder.indexOf(b.phase);
        const pa = a.phase === readinessPhase ? -1 : (ia < 0 ? 99 : ia);
        const pb = b.phase === readinessPhase ? -1 : (ib < 0 ? 99 : ib);
        if (a.ready !== b.ready) return a.ready ? 1 : -1;
        return pa - pb;
      }});
      const unmet = sorted.filter(v => !v.ready);
      const show = unmet.slice(0, 3);
      if (!show.length) return '';
      let html = '<div class="note-block-label">TODO</div>';
      show.forEach(v => {{
        const pending = (v.prerequisites || []).find(p => !p.met);
        const line = pending ? pending.label : (v.note || v.title);
        html += `<div class="note-todo">[ ] ${{v.title}} — ${{line}}</div>`;
      }});
      return html;
    }}

    function renderSessionNotes() {{
      const prog = opsProgress();
      const creds = OPS.creds || [];
      const clues = OPS.clues || [];
      const hashes = OPS.hashes || [];
      const quests = getDisplayQuests();
      let html = '';
      if (creds.length) {{
        html += '<div class="note-block-label">Credentials</div>';
        creds.forEach(c => {{
          const cls = c.status === 'valid' ? 'ok' : 'warn';
          html += noteKv(c.user, c.status, cls);
        }});
      }}
      if (prog.loot && clues.length) {{
        html += '<div class="note-block-label">Loot</div>';
        clues.forEach(c => {{
          html += noteKv(c.user, `«${{c.string}}»`, 'warn');
          if (c.source) html += noteKvIndent('archivo', c.source, 'dim');
        }});
      }}
      if (prog.acls && quests.length && !isInspectingOther()) {{
        html += '<div class="note-block-label">PrivEsc / ACL</div>';
        quests.forEach(q => {{
          const st = q.enabled ? 'verificado' : 'bloqueado';
          html += noteKv(`${{q.principal}}`, `${{q.technique}} → ${{q.target}} (${{st}})`, q.enabled ? 'ok' : 'warn');
        }});
      }}
      const attackPaths = getDisplayAttackPaths();
      if (attackPaths.length && !isInspectingOther()) {{
        html += '<div class="note-block-label">Caminos de ataque</div>';
        attackPaths.slice(0, 10).forEach(p => {{
          const sev = (p.impact === 'critical' ? 'danger' : (p.impact === 'high' ? 'warn' : ''));
          html += noteKv(p.source_label || p.source, `${{p.target_label || p.target}} · ${{p.impact}}`, sev);
          p.steps && p.steps.forEach(s => {{
            html += noteKvIndent(s.edge_type, s.narrative || '', 'dim');
          }});
        }});
      }}
      if (prog.exploit && hashes.length) {{
        html += '<div class="note-block-label">Hashes / PTH</div>';
        hashes.forEach(h => {{
          html += noteKv(h.account, h.nthash, 'ok');
          const pth = (OPS.pth_sessions || []).find(p => p.account === h.account);
          if (pth && pth.winrm_cmd) html += noteKvIndent('winrm', pth.winrm_cmd, 'dim');
        }});
      }}
      return html;
    }}

    function renderOperatorSetupNote(setup) {{
      setup = setup || {{}};
      const warnings = [];
      if (!setup.clock_ready) warnings.push('Kerberos puede fallar — sincroniza reloj o libfaketime');
      if (setup.gssapi_installed === false) warnings.push('Falta gssapi — pip install admapper[full]');
      const cmds = [];
      if (setup.sync_dc_cmd) cmds.push(['Todo en uno', setup.sync_dc_cmd]);
      if (setup.sync_clock_cmd) cmds.push(['Solo reloj', setup.sync_clock_cmd]);
      if (setup.install_faketime_cmd && !setup.libfaketime_installed) {{
        cmds.push(['libfaketime', setup.install_faketime_cmd]);
      }}
      if (setup.hosts_entry) cmds.push(['/etc/hosts', setup.hosts_entry]);
      if (!warnings.length && !cmds.length) return '';
      let html = '<details><summary>Prep local</summary>';
      warnings.forEach(w => {{ html += noteKv('Aviso', w, 'warn'); }});
      if (setup.clock_ready) html += noteKv('Reloj', 'OK', 'ok');
      if (setup.gssapi_installed) html += noteKv('gssapi', 'OK', 'ok');
      cmds.forEach(([label, cmd]) => {{
        html += noteKv(label, cmd, 'dim');
      }});
      (setup.notes || []).forEach(n => {{ html += noteKvIndent('nota', n, 'dim'); }});
      html += '</details>';
      return html;
    }}

    function renderAttackReadinessFull(intel) {{
      let vectors = filterAttackVectors((intel || {{}}).attack_readiness || []);
      if (!vectors.length) return '<p class="hl">Sin vectores — escanea el objetivo</p>';
      const phaseOrder = ['recon', 'creds', 'enum', 'loot', 'escalate'];
      const sorted = [...vectors].sort((a, b) => {{
        const ia = phaseOrder.indexOf(a.phase);
        const ib = phaseOrder.indexOf(b.phase);
        return (ia < 0 ? 99 : ia) - (ib < 0 ? 99 : ib);
      }});
      let html = '';
      sorted.forEach(v => {{
        const mark = v.ready ? '✓' : '○';
        const color = v.ready ? 'var(--success)' : 'var(--warn)';
        html += `<p><span style="color:${{color}}">${{mark}}</span> <strong>${{v.title}}</strong> <span class="chip">${{v.phase}}</span></p>`;
        if (v.note) html += `<p class="sub">${{v.note}}</p>`;
        html += '<ul class="list">';
        (v.prerequisites || []).forEach(p => {{
          const pm = p.met ? '✓' : '✗';
          const pc = p.met ? 'var(--muted)' : 'var(--danger)';
          html += `<li><span style="color:${{pc}}">${{pm}}</span> ${{p.label}}<div class="sub">${{p.detail || ''}}</div></li>`;
        }});
        html += '</ul>';
      }});
      return html;
    }}

    function renderLockoutReference(intel) {{
      const lp = (intel || {{}}).lockout_policy || {{}};
      const budget = (intel || {{}}).lockout_budget || [];
      if (!lp.lockout_enabled && !lp.lockout_threshold) {{
        return noteKv('Lockout', 'sin datos LDAP aún', 'dim');
      }}
      const thresh = lp.lockout_threshold || 0;
      const dur = lp.duration_minutes != null ? lp.duration_minutes + ' min' : '—';
      const win = lp.window_minutes != null ? lp.window_minutes + ' min' : '—';
      let html = noteKv('Umbral', String(thresh));
      html += noteKv('Duración', dur, 'dim');
      html += noteKv('Ventana', win, 'dim');
      if (lp.error) html += noteKv('Error', lp.error, 'warn');
      budget.slice(0, 12).forEach(b => {{
        const rem = b.attempts_remaining != null ? b.attempts_remaining : '∞';
        html += noteKvIndent(b.username, `badPwd=${{b.bad_pwd_count}} · restantes ${{rem}}`, 'dim');
      }});
      if (budget.length > 12) html += noteKvIndent('…', `+${{budget.length - 12}} usuarios`, 'dim');
      return html;
    }}

    function renderDomainUsersReference(intel) {{
      const users = (intel || {{}}).domain_users || [];
      if (!users.length) return noteKv('Users', 'sin enum LDAP', 'dim');
      let html = '';
      users.forEach(u => {{
        const en = u.enabled ? 'enabled' : 'disabled';
        const flags = (u.flags || []).join(', ');
        const spns = u.spn_count ? ` · spn:${{u.spn_count}}` : '';
        html += noteKv(u.username, `${{en}}${{spns}}${{flags ? ' · ' + flags : ''}}`, u.enabled ? '' : 'dim');
      }});
      return html;
    }}

    function renderPistaAnalysisReference(intel) {{
      const pa = (intel || {{}}).password_analysis || {{}};
      const rules = pa.rules || [];
      const inferences = pa.inferences || [];
      const transforms = pa.possible_transforms || [];
      if (!rules.length && !inferences.length) {{
        return noteKv('Pista', 'sin reglas parseadas', 'dim');
      }}
      let html = '';
      rules.forEach(r => {{
        const label = r.label || r.rule || 'regla';
        html += noteKvIndent('regla', `${{label}} · ${{r.user}}`, 'warn');
      }});
      inferences.forEach(inf => {{
        html += noteKvIndent('inferencia', inf.summary || inf.label || inf.reasoning || '', 'dim');
      }});
      transforms.forEach(t => {{
        html += noteKvIndent(t.transform, `${{t.user}} — ${{t.description}}`, 'dim');
      }});
      return html;
    }}

    function renderStudyMapReference() {{
      const rows = OPS.study_map || [];
      if (!rows.length) return '';
      let body = '';
      rows.forEach(r => {{
        body += `<tr><td>P${{String(r.order).padStart(2,'0')}}</td><td>${{r.name}}</td>`
          + `<td>${{r.crtp}}</td><td>${{r.crte !== '—' ? r.crte : ''}}</td>`
          + `<td>${{r.crto !== '—' ? r.crto : ''}}</td>`
          + `<td>${{(r.mitre || []).join(', ')}}</td></tr>`;
      }});
      return `<table class="study-map"><thead><tr><th>#</th><th>Fase</th><th>CRTP</th><th>CRTE</th><th>CRTO</th><th>MITRE</th></tr></thead>`
        + `<tbody>${{body}}</tbody></table>`;
    }}

    function renderReferenceDetails(intel) {{
      const prog = opsProgress();
      let html = '<div class="note-section"><div class="note-block-label">Referencia</div>';
      html += '<details><summary>Mapa de estudio (CRTP · CRTE · CRTO)</summary>';
      html += renderStudyMapReference();
      html += '</details>';
      html += '<details><summary>Prerrequisitos por ataque (matriz completa)</summary>';
      html += renderAttackReadinessFull(intel);
      html += '</details>';
      if (prog.enum_users) {{
        html += '<details><summary>Política de bloqueo</summary>';
        html += renderLockoutReference(intel);
        html += '</details>';
        html += '<details><summary>Usuarios del dominio</summary>';
        html += renderDomainUsersReference(intel);
        html += '</details>';
      }}
      if (prog.loot) {{
        html += '<details><summary>Análisis de pista</summary>';
        html += renderPistaAnalysisReference(intel);
        html += '</details>';
      }}
      html += '</div>';
      return html;
    }}

    function renderNotesDoc() {{
      const intel = OPS.engagement_intel || {{}};
      let html = '<div class="notes-doc"><div class="notes-title">NOTAS</div>';
      html += renderNotesHeader();
      html += '<div class="note-section">';
      html += renderInfraFocusNote();
      html += renderPivotNote();
      if (!graphFocus) html += renderNextStepsNote(intel);
      html += renderTargetBlock();
      html += renderSessionNotes();
      html += '</div>';
      html += renderOperatorSetupNote(OPS.operator_setup);
      html += renderReferenceDetails(intel);
      html += '</div>';
      return html;
    }}

    function renderRight() {{
      $('right').innerHTML = renderNotesDoc();
      document.querySelectorAll('.quest-list li').forEach(li => {{
        if (!li.dataset.mid) return;
        li.onclick = () => {{
          selectedMissionId = li.dataset.mid;
          renderLeft();
          renderRight();
          highlightMissionEdge(selectedMissionId);
        }};
      }});
      const btnClearInfra = $('btn-clear-infra');
      if (btnClearInfra) btnClearInfra.onclick = () => {{ infraFocus = null; renderRight(); }};
    }}

    function highlightMissionEdge(missionId) {{
      if (!edgeData || !missionId) return;
      edgeData.get().forEach(e => {{
        const active = e.mission_id === missionId;
        edgeData.update({{
          id: e.id,
          width: active ? 6 : (e.mission_id ? 4 : 2),
          color: {{ color: active ? '#3dffcf' : (e.mission_id ? '#f59e0b' : '#4a5568') }},
        }});
      }});
    }}

    function renderBookPage(idx) {{
      const book = OPS.pentest_book || {{}};
      const pages = book.pages || [];
      if (!pages.length) return;
      bookPageIdx = Math.max(0, Math.min(idx, pages.length - 1));
      const pg = pages[bookPageIdx];
      const reader = $('book-reader');
      if (!reader) return;
      let html = '<div class="book-header">';
      html += `<div class="book-chapter">${{pg.chapter}} · página ${{pg.page}}</div>`;
      html += `<h1>${{pg.title}}</h1>`;
      if (pg.mitre) html += `<div class="book-meta">MITRE ${{pg.mitre}}</div>`;
      html += '</div>';
      html += '<div class="book-toc">';
      (book.chapters || []).forEach(ch => {{
        const active = ch.name === pg.chapter ? ' active' : '';
        html += `<button type="button" class="${{active}}" data-ch="${{ch.first_page_id}}">${{ch.name}}</button>`;
      }});
      html += '</div>';
      (pg.sections || []).forEach(sec => {{
        html += '<div class="book-section">';
        if (sec.type === 'paragraph') html += `<p>${{sec.text}}</p>`;
        else if (sec.type === 'list') html += '<ul>' + (sec.items || []).map(i => `<li>${{i}}</li>`).join('') + '</ul>';
        else if (sec.type === 'table') {{
          html += '<table><thead><tr>' + (sec.headers || []).map(h => `<th>${{h}}</th>`).join('') + '</tr></thead><tbody>';
          (sec.rows || []).forEach(row => {{ html += '<tr>' + row.map(c => `<td>${{c}}</td>`).join('') + '</tr>'; }});
          html += '</tbody></table>';
        }} else if (sec.type === 'code') html += `<pre>${{sec.text}}</pre>`;
        else if (sec.type === 'diagram') html += `<div class="book-diagram">${{sec.svg}}</div>`;
        html += '</div>';
      }});
      if ((pg.related_vectors || []).length) {{
        html += `<div class="book-meta">Vectores relacionados: ${{pg.related_vectors.join(', ')}}</div>`;
      }}
      html += `<div class="book-nav">
        <button type="button" id="book-prev" ${{bookPageIdx <= 0 ? 'disabled' : ''}}>◀ Anterior</button>
        <span class="book-meta">${{bookPageIdx + 1}} / ${{pages.length}}</span>
        <button type="button" id="book-next" ${{bookPageIdx >= pages.length - 1 ? 'disabled' : ''}}>Siguiente ▶</button>
      </div>`;
      reader.innerHTML = html;
      reader.querySelectorAll('.book-toc button').forEach(btn => {{
        btn.onclick = () => {{
          const id = btn.dataset.ch;
          const i = pages.findIndex(p => p.id === id);
          if (i >= 0) renderBookPage(i);
        }};
      }});
      const prev = $('book-prev');
      const next = $('book-next');
      if (prev) prev.onclick = () => renderBookPage(bookPageIdx - 1);
      if (next) next.onclick = () => renderBookPage(bookPageIdx + 1);
    }}

    function showManualView() {{
      viewMode = 'manual';
      $('graph').style.display = 'none';
      $('scan-overlay').style.display = 'none';
      const reader = $('book-reader');
      if (reader) {{ reader.hidden = false; renderBookPage(bookPageIdx); }}
    }}

    function showGraphView() {{
      $('graph').style.display = '';
      $('scan-overlay').style.display = '';
      const reader = $('book-reader');
      if (reader) reader.hidden = true;
    }}

    function graphSignature() {{
      const g = activeGraphData();
      const ids = (g.nodes || []).map(n => n.id).sort().join(',');
      return viewMode + '|' + ids + '|' + (g.edges || []).length;
    }}

    function syncGraph() {{
      if (screen !== 'play') return;
      const sig = graphSignature();
      if (network && sig === lastGraphSig) {{
        highlightIdentityGraph();
        const mid = (currentMission() || {{}}).id;
        if (mid) highlightMissionEdge(mid);
        return;
      }}
      lastGraphSig = sig;
      initGraph();
    }}

    function initGraph() {{
      if (viewMode === 'manual') {{
        showManualView();
        return;
      }}
      showGraphView();
      if (typeof vis === 'undefined') {{
        termLine('vis-network no cargado — revisa conexión CDN', 'line-error');
        return;
      }}
      const g = activeGraphData();
      const container = $('graph');
      if (!container) return;

      const nodes = (g.nodes || []).map(n => {{
        const baseColor = typeof n.color === 'string' ? n.color : '#64748b';
        const font = n.font || {{ color: '#f8fafc', strokeWidth: 3, strokeColor: '#080b10', size: 11 }};
        return {{
          ...n,
          font,
          shadow: {{ enabled: true, color: 'rgba(0,0,0,0.35)', size: 8 }},
        }};
      }});
      const edges = g.edges || [];

      const physicsOpts = {{
        enabled: true,
        stabilization: {{ iterations: 120, fit: true }},
        barnesHut: {{
          gravitationalConstant: -4000,
          centralGravity: 0.15,
          springLength: 200,
          springConstant: 0.05,
          avoidOverlap: 0.8,
        }},
      }};

      if (network) {{
        nodeData.clear();
        edgeData.clear();
        nodeData.add(nodes);
        edgeData.add(edges);
        network.setOptions({{ physics: {{ enabled: false }} }});
        highlightIdentityGraph();
        const mid = (currentMission() || {{}}).id;
        if (mid) highlightMissionEdge(mid);
        return;
      }}

      nodeData = new vis.DataSet(nodes);
      edgeData = new vis.DataSet(edges);
      const usePhysics = viewMode === 'ad';
      const netNodeSize = viewMode === 'network' ? 14 : 22;
      network = new vis.Network(container, {{ nodes: nodeData, edges: edgeData }}, {{
        physics: usePhysics ? physicsOpts : {{ enabled: false }},
        interaction: {{ hover: true, zoomView: true, dragView: true }},
        nodes: {{
          shape: 'dot',
          size: netNodeSize,
          borderWidth: 2,
          font: {{ size: 11, face: 'IBM Plex Sans, sans-serif', align: 'center' }},
        }},
        edges: {{
          color: {{ color: '#4a5568', highlight: '#3dffcf' }},
          font: {{ color: '#7a8699', size: 9, strokeWidth: 0 }},
          smooth: {{ type: 'continuous' }},
          width: 2,
        }},
      }});
      network.once('stabilizationIterationsDone', () => {{
        network.setOptions({{ physics: {{ enabled: false }} }});
        if (!graphPulseDone && viewMode === 'ad') {{
          pulseDiscovered(nodes);
          graphPulseDone = true;
        }}
        highlightIdentityGraph();
        const mid = (currentMission() || {{}}).id;
        if (mid) highlightMissionEdge(mid);
      }});
      network.on('click', (params) => {{
        if (params.nodes.length) {{
          selectIdentityFromNode(nodeData.get(params.nodes[0]));
          return;
        }}
        if (!params.edges.length || !edgeData) return;
        const edge = edgeData.get(params.edges[0]);
        if (!edge || !edge.mission_id) return;
        selectedMissionId = edge.mission_id;
        renderLeft();
        renderRight();
        highlightMissionEdge(edge.mission_id);
      }});
    }}

    function pulseDiscovered(nodes) {{
      if (!nodeData) return;
      nodes.forEach((n, i) => {{
        setTimeout(() => {{
          try {{
            nodeData.update({{ id: n.id, size: 28 }});
            setTimeout(() => nodeData.update({{ id: n.id, size: 22 }}), 400);
          }} catch (e) {{}}
        }}, i * 120);
      }});
    }}

    function animateExploitEdge() {{
      if (!edgeData) return;
      const edges = edgeData.get();
      edges.forEach(e => {{
        edgeData.update({{ id: e.id, color: {{ color: '#3dffcf' }}, width: 4 }});
      }});
      setTimeout(() => {{
        edges.forEach(e => {{
          edgeData.update({{ id: e.id, color: {{ color: '#4a5568' }}, width: 2 }});
        }});
      }}, 1200);
    }}

    function renderAll() {{
      renderPhases();
      renderHudMeta();
      renderLeft();
      renderRight();
      if (screen === 'play') syncGraph();
    }}

    async function refreshAfterOp(ok) {{
      await fetchState();
      if (graphFocus) {{
        const still = (OPS.selectable_identities || []).some(
          i => i.username.toLowerCase() === graphFocus.toLowerCase()
        );
        if (!still) graphFocus = null;
      }}
      renderAll();
      highlightIdentityGraph();
      if (ok) {{
        flash('ok');
        animateExploitEdge();
      }} else {{
        flash('err');
      }}
    }}

    async function postOp(endpoint, body, label) {{
      setOpState(true);
      typeLine('> ' + label, 'line-cmd');
      try {{
        const r = await fetch(endpoint, {{
          method: 'POST',
          headers: {{ 'Content-Type': 'application/json' }},
          body: JSON.stringify(body),
        }});
        if (r.status === 409) {{
          termLine('operación ya en curso', 'line-error');
          setOpState(false);
          return false;
        }}
        if (!r.ok) {{
          termLine('error HTTP ' + r.status, 'line-error');
          setOpState(false);
          flash('err');
          return false;
        }}
        return true;
      }} catch (e) {{
        termLine('error de red: ' + e, 'line-error');
        setOpState(false);
        flash('err');
        return false;
      }}
    }}

    async function runAction(act) {{
      if (!act || opRunning) return;
      if (!API_MODE) {{
        termLine('Modo estático — inicia: admapper dashboard -w <workspace>', 'line-error');
        return;
      }}
      const action = act.action || 'exploit';
      let body = {{}};
      if (action === 'run') {{
        body.username = ($('cred-user') || {{}}).value || '';
        body.password = ($('cred-pass') || {{}}).value || '';
        if (!body.username || !body.password) {{
          termLine('Introduce usuario y contraseña', 'line-error');
          return;
        }}
      }}
      if (action === 'brief') body.auto = !!act.auto;
      if (action === 'spray') {{
        body.password = ($('spray-pass') || {{}}).value || '';
        if (!body.password) {{
          termLine('Introduce contraseña para spray (campo spray-pass)', 'line-error');
          return;
        }}
      }}
      const m = act.mission || {{}};
      await postOp('/api/' + action, body, act.button || action);
    }}

    function connectEvents() {{
      if (!API_MODE || evtSource) return;
      evtSource = new EventSource('/api/events');
      evtSource.onmessage = (ev) => {{
        let data;
        try {{ data = JSON.parse(ev.data); }} catch {{ return; }}
        const kind = data.type || 'log';
        const line = data.line || '';
        if (kind === 'state') {{
          try {{
            const st = JSON.parse(line);
            if (st.refresh) {{
              setOpState(false);
              refreshAfterOp(true);
            }}
          }} catch {{}}
          return;
        }}
        const cls = kind === 'error' ? 'line-error' : (kind === 'cmd' ? 'line-cmd' : (kind === 'phase' ? 'line-phase' : ''));
        if (kind === 'done') {{
          termLine(line, cls);
          setOpState(false);
          refreshAfterOp(true);
        }} else if (kind === 'error' && line.startsWith('[exit')) {{
          termLine(line, 'line-error');
          setOpState(false);
          refreshAfterOp(false);
        }} else {{
          termLine(line, cls);
        }}
      }};
      evtSource.onerror = () => {{ /* reconnect handled by browser */ }};
    }}

    $('boot-ip').addEventListener('keydown', (ev) => {{
      if (ev.key === 'Enter') submitBootIp();
    }});

    function setMapTab(mode) {{
      viewMode = mode;
      ['tab-network', 'tab-ad', 'tab-manual'].forEach(id => $(id).classList.remove('active'));
      $('tab-' + (mode === 'ad' ? 'ad' : mode === 'manual' ? 'manual' : 'network')).classList.add('active');
      network = null;
      lastGraphSig = '';
      initGraph();
    }}
    $('tab-network').onclick = () => setMapTab('network');
    $('tab-ad').onclick = () => setMapTab('ad');
    $('tab-manual').onclick = () => setMapTab('manual');
    $('tab-hq').onclick = () => enterHQ(true);

    document.addEventListener('keydown', (ev) => {{
      if (screen === 'hq') {{
        if (['ArrowUp','ArrowDown','ArrowLeft','ArrowRight',' '].includes(ev.key)) ev.preventDefault();
        hqKeys[ev.key] = true;
        if (ev.key === 'e' || ev.key === 'E') {{
          ev.preventDefault();
          hqInteract();
        }}
        if (ev.key === 'Escape') {{
          const dlg = $('hq-dialog');
          if (dlg && !dlg.classList.contains('hidden')) dlg.classList.add('hidden');
        }}
      }}
      if (screen === 'play' && ev.key === 'h' && !ev.ctrlKey && !ev.metaKey) {{
        const tag = (document.activeElement || {{}}).tagName || '';
        if (tag !== 'INPUT' && tag !== 'TEXTAREA') enterHQ(true);
      }}
    }});
    document.addEventListener('keyup', (ev) => {{
      if (screen === 'hq') hqKeys[ev.key] = false;
    }});

    (function bootOrPlay() {{
      initBoot();
      if ((OPS.meta || {{}}).blackbox === false && (OPS.topology || {{}}).has_scan) {{
        enterHQ();
      }} else {{
        showScreen('boot');
        connectEvents();
      }}
    }})();
  </script>
</body>
</html>"""


def write_ops_html(
    ws_path: Path,
    *,
    workspace: str,
    domain: str | None,
    owned_users: list[str] | None = None,
    pivot_user: str | None = None,
) -> Path:
    out = ws_path / "ad_ops.html"
    out.write_text(
        build_ops_html(
            ws_path,
            workspace=workspace,
            domain=domain,
            owned_users=owned_users,
            pivot_user=pivot_user,
            api_mode=False,
        ),
        encoding="utf-8",
    )
    return out
