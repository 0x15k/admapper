---
name: admapper-ui-architecture
description: Guidelines for modifying, designing, and maintaining the ADMapper dark web dashboard, Vis.js graph UI, and terminal filter system.
---

# ADMapper UI Architecture Guidelines

This skill defines the visual, structural, and behavioral standards for the ADMapper web-based pentesting dashboard. Follow these guidelines strictly when making modifications to the dashboard layout, stylesheet, or client-side JavaScript.

## 1. Design System & Visual Guidelines
- **Base Theme**: Pure dark hacker/terminal aesthetic.
  - Background: `#0d1117` (Deep Dark) or `#0a0e14`.
  - Foreground Text: `#c9d1d9` (Muted white) and `#8b949e` (Secondary).
  - Borders: `#30363d` or `#21262d`.
  - Accent/Focus: `#58a6ff` (Bright Blue) and `#1f6feb` (Deep Blue).
- **Node Classification & Colors**:
  - **High Value Targets** (Domain Controllers, Domain Admins): Styled with bright borders or red/orange indicators.
  - **Compromised Elements**: Solid green indicator (`#2ea44f` or `#3fb950`).
  - **Pivot Identity**: Highlighted using cyan (`#00f0ff` or `#39c5bb`).
  - **Attack Paths**: Represented with dashed, pulsing edges.
- **Side Panels**:
  - A fixed-width sidebar (approx. `320px` to `350px`) on the right containing unified Loot, Credential lists, and Accordion-based findings.
  - Scroll behavior must be localized (`overflow-y: auto`) to avoid moving the entire page.

## 2. Interactive Terminal Logs
- **Log Formatting**: The backend sends terminal lines to the frontend in a stream. Each line starts with a marker:
  - `✓` or `[success]`: Success messages (e.g., target scan completed). Color: green.
  - `→` or `[info]`: Informational steps. Color: cyan.
  - `!` or `[warning]`: Non-critical alerts or skipped checks. Color: yellow.
  - `✗` or `[error]`: Failures. Color: red.
- **Copy Commands**:
  - When suggesting commands to run (e.g., `evil-winrm`), use the `data-copy-val` attribute on a clickable badge or element.
  - Do NOT write inline `onclick="navigator.clipboard.writeText('...')"`. Double/single quote escaping on command flags (e.g., `-u 'logging.htb\user'`) will break the HTML parsing.
  - Use a centralized document-level click handler for `data-copy-val` attributes.

## 3. Graph Filtering and Visualization
- **Filters**: Provide real-time graph filtering:
  - **All**: Shows the entire Active Directory tree.
  - **High Value**: Domain Admins and Controllers only.
  - **Compromised**: Users and computers marked as owned.
  - **Attack Path**: Displays direct routes from current pivots to High Value targets.
- **Network Layout**: Keep physics enabled initially, but transition to fixed positions to prevent excessive CPU usage during subsequent graph refreshes.

## 4. UI Framework Constraints
- **Zero Framework Rule**: Do NOT use external frameworks (React, Vue, Tailwind) unless explicitly requested. Rely strictly on Vanilla JS, semantic HTML5, and native CSS3 variables.
