"""ACL attack-flow diagram for the pentest manual (generic, not lab-specific)."""

ACL_ATTACK_FLOW_SVG = """<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 920 720" role="img" aria-label="Flujo de abuso ACL en AD">
  <defs>
    <marker id="arrow" markerWidth="8" markerHeight="8" refX="6" refY="3" orient="auto">
      <path d="M0,0 L6,3 L0,6 Z" fill="#8b9cb3"/>
    </marker>
    <style>
      .box { fill:#1a2332; stroke:#3dffcf; stroke-width:1.5; rx:6; }
      .crit { stroke:#ff4d6a; fill:#2a1520; }
      .perm { stroke:#c9a66b; fill:#1f1a14; }
      .attr { stroke:#a78bfa; fill:#1a1528; }
      .inj  { stroke:#22c55e; fill:#142018; }
      .goal { stroke:#60a5fa; fill:#141e2e; }
      .tool { stroke:#8b9cb3; fill:#10151c; stroke-dasharray:4 3; }
      .t { fill:#e8edf4; font:600 13px 'IBM Plex Sans',sans-serif; }
      .s { fill:#8b9cb3; font:11px 'IBM Plex Sans',sans-serif; }
      .edge { stroke:#5a6a80; stroke-width:1.2; fill:none; marker-end:url(#arrow); stroke-dasharray:5 4; }
    </style>
  </defs>
  <rect width="920" height="720" fill="#080b10"/>
  <text x="460" y="28" text-anchor="middle" class="t" font-size="15">Abuso de ACLs — flujo de escalada (genérico)</text>

  <rect class="box crit" x="360" y="44" width="200" height="44"/>
  <text x="460" y="64" text-anchor="middle" class="t">Atacante</text>
  <text x="460" y="80" text-anchor="middle" class="s">usuario comprometido</text>

  <rect class="tool" x="80" y="108" width="200" height="40"/>
  <text x="180" y="133" text-anchor="middle" class="s">BloodHound / SharpHound</text>
  <rect class="tool" x="640" y="108" width="200" height="40"/>
  <text x="740" y="133" text-anchor="middle" class="s">PowerView / ADACLScanner</text>
  <path class="edge" d="M460 88 L180 108"/>
  <path class="edge" d="M460 88 L740 108"/>

  <rect class="perm crit" x="60" y="178" width="170" height="48"/>
  <text x="145" y="198" text-anchor="middle" class="t">GenericAll</text>
  <text x="145" y="214" text-anchor="middle" class="s">control total</text>

  <rect class="perm" x="250" y="178" width="170" height="48"/>
  <text x="335" y="198" text-anchor="middle" class="t">WriteDACL</text>
  <text x="335" y="214" text-anchor="middle" class="s">modificar DACL</text>

  <rect class="perm" x="440" y="178" width="170" height="48"/>
  <text x="525" y="198" text-anchor="middle" class="t">WriteOwner</text>
  <text x="525" y="214" text-anchor="middle" class="s">tomar ownership</text>

  <rect class="perm" x="630" y="178" width="170" height="48"/>
  <text x="715" y="198" text-anchor="middle" class="t">ForceChangePassword</text>
  <text x="715" y="214" text-anchor="middle" class="s">reset sin conocer pwd</text>

  <path class="edge" d="M180 148 L145 178"/>
  <path class="edge" d="M460 148 L335 178"/>
  <path class="edge" d="M460 148 L525 178"/>
  <path class="edge" d="M740 148 L715 178"/>

  <rect class="attr" x="40" y="268" width="200" height="48"/>
  <text x="140" y="288" text-anchor="middle" class="t">Shadow Credentials</text>
  <text x="140" y="304" text-anchor="middle" class="s">msDS-KeyCredentialLink</text>

  <rect class="perm crit" x="270" y="268" width="160" height="48"/>
  <text x="350" y="288" text-anchor="middle" class="t">DCSync</text>
  <text x="350" y="304" text-anchor="middle" class="s">replicación AD</text>

  <rect class="attr" x="460" y="268" width="200" height="48"/>
  <text x="560" y="288" text-anchor="middle" class="t">RBCD Abuse</text>
  <text x="560" y="304" text-anchor="middle" class="s">AllowedToActOnBehalf</text>

  <rect class="inj" x="690" y="268" width="180" height="48"/>
  <text x="780" y="288" text-anchor="middle" class="t">ACE Injection</text>
  <text x="780" y="304" text-anchor="middle" class="s">Add-DomainObjectAcl</text>

  <path class="edge" d="M145 226 L140 268"/>
  <path class="edge" d="M145 226 L350 268"/>
  <path class="edge" d="M145 226 L560 268"/>
  <path class="edge" d="M335 226 L780 268"/>
  <path class="edge" d="M525 226 L780 268"/>
  <path class="edge" d="M780 316 L350 340"/>

  <rect class="goal" x="80" y="358" width="200" height="44"/>
  <text x="180" y="378" text-anchor="middle" class="t">Usuario / Admin</text>
  <text x="180" y="394" text-anchor="middle" class="s">hash o reset pwd</text>

  <rect class="goal" x="360" y="358" width="200" height="44"/>
  <text x="460" y="378" text-anchor="middle" class="t">Grupo privilegiado</text>
  <text x="460" y="394" text-anchor="middle" class="s">AddMember / GPO</text>

  <rect class="goal" x="640" y="358" width="200" height="44"/>
  <text x="740" y="378" text-anchor="middle" class="t">Objeto dominio</text>
  <text x="740" y="394" text-anchor="middle" class="s">DCSync / Golden Ticket</text>

  <path class="edge" d="M140 316 L180 358"/>
  <path class="edge" d="M715 226 L180 380"/>
  <path class="edge" d="M560 316 L460 358"/>
  <path class="edge" d="M350 316 L740 358"/>

  <rect class="box crit" x="330" y="448" width="260" height="52"/>
  <text x="460" y="472" text-anchor="middle" class="t">Domain Admin</text>
  <text x="460" y="490" text-anchor="middle" class="s">objetivo final de la cadena ACL</text>

  <path class="edge" d="M180 402 L400 448"/>
  <path class="edge" d="M460 402 L460 448"/>
  <path class="edge" d="M740 402 L520 448"/>

  <text x="40" y="540" class="s">Leyenda:</text>
  <rect class="perm crit" x="40" y="552" width="14" height="14"/><text x="60" y="564" class="s">Crítico</text>
  <rect class="perm" x="130" y="552" width="14" height="14"/><text x="150" y="564" class="s">ACL / permiso</text>
  <rect class="attr" x="240" y="552" width="14" height="14"/><text x="260" y="564" class="s">Atributo AD</text>
  <rect class="inj" x="350" y="552" width="14" height="14"/><text x="370" y="564" class="s">Inyección ACE</text>
  <rect class="goal" x="470" y="552" width="14" height="14"/><text x="490" y="564" class="s">Objetivo intermedio</text>
  <line x1="600" y1="559" x2="630" y2="559" class="edge" marker-end="url(#arrow)"/>
  <text x="640" y="564" class="s">Flujo de ataque</text>
</svg>"""
