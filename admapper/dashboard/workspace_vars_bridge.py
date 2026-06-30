"""Shared workspace variable state — syncs Ops Commands tab and Cheatsheet sidebar."""

WORKSPACE_VARS_JS = r"""
const WorkspaceVars = (function () {
  var store = {};
  var applying = false;
  var persistTimer = null;

  var CC_FIELDS = {
    DOMAIN: 'cc-domain',
    DC_IP: 'cc-dc',
    USERNAME: 'cc-user',
    PASSWORD: 'cc-pass',
    NTLM_HASH: 'cc-hash',
    ATTACKER_IP: 'cc-attacker',
    CA_NAME: 'cc-ca',
    TEMPLATE: 'cc-template'
  };

  function get() {
    var base = (typeof state !== 'undefined' && state.cheatsheet_vars)
      ? Object.assign({}, state.cheatsheet_vars) : {};
    return Object.assign(base, store);
  }

  function readiness() {
    var v = get();
    var dc = (v.DC_IP || '').trim();
    var user = (v.USERNAME || '').trim();
    var pass = (v.PASSWORD || '').trim();
    var hash = (v.NTLM_HASH || '').trim();
    var missing = [];
    if (!dc) missing.push('DC / target IP');
    if (!user) missing.push('username');
    if (!pass && !hash) missing.push('password or NTLM hash');
    return {
      scan_ready: !!dc,
      auth_ready: !!dc && !!user && (!!pass || !!hash),
      missing: missing
    };
  }

  function set(updates, opts) {
    opts = opts || {};
    Object.keys(updates || {}).forEach(function (k) {
      var key = (k === 'workspace') ? 'workspace' : String(k).toUpperCase();
      if (updates[k] !== undefined && updates[k] !== null) store[key] = String(updates[k]);
    });
    if (!opts.silent) applyToViews();
    if (!opts.skipPersist) schedulePersist();
    if (typeof state !== 'undefined') {
      state.cheatsheet_vars = get();
      state.workspace_readiness = readiness();
    }
    updateReadinessUI();
  }

  function schedulePersist() {
    if (persistTimer) clearTimeout(persistTimer);
    persistTimer = setTimeout(persistNow, 400);
  }

  function persistNow() {
    if (typeof state !== 'undefined' && state.workspace_required) {
      return Promise.resolve();
    }
    return fetch('/api/workspace/seed', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ workspace_vars: get() })
    }).then(function (r) { return r.json(); }).then(function (data) {
      if (data.state && typeof renderState === 'function') {
        renderState(data.state);
      } else if (data.state) {
        syncFromState(data.state);
      }
      updateReadinessUI();
      return data;
    }).catch(function () {});
  }

  function applyToViews() {
    applying = true;
    var v = get();
    Object.keys(CC_FIELDS).forEach(function (key) {
      var el = document.getElementById(CC_FIELDS[key]);
      if (el && v[key] !== undefined && el.value !== String(v[key])) {
        el.value = String(v[key]);
      }
    });
    var panel = document.getElementById('cs-vars-panel');
    if (panel) {
      panel.querySelectorAll('input[data-cs-var]').forEach(function (inp) {
        var key = inp.getAttribute('data-cs-var');
        if (v[key] !== undefined && inp.value !== String(v[key])) {
          inp.value = String(v[key]);
        }
      });
    }
    syncTerminalFromVars();
    applying = false;
    if (typeof CommandCheatsheet !== 'undefined' && CommandCheatsheet.render) {
      CommandCheatsheet.render();
    }
    if (typeof CheatsheetView !== 'undefined' && CheatsheetView.renderCommands) {
      CheatsheetView.renderCommands();
    }
  }

  function syncTerminalFromVars() {
    var v = get();
    var ip = document.getElementById('input-ip');
    var user = document.getElementById('input-user');
    var pass = document.getElementById('input-pass');
    if (ip && v.DC_IP !== undefined) ip.value = v.DC_IP || '';
    if (user && v.USERNAME !== undefined) user.value = v.USERNAME || '';
    if (pass && v.PASSWORD !== undefined) pass.value = v.PASSWORD || '';
  }

  function applyTerminalToVars() {
    var ip = document.getElementById('input-ip');
    var user = document.getElementById('input-user');
    var pass = document.getElementById('input-pass');
    var patch = {};
    if (ip) patch.DC_IP = ip.value.trim();
    if (user) patch.USERNAME = user.value.trim();
    if (pass) patch.PASSWORD = pass.value;
    set(patch, { skipPersist: true });
    return patch;
  }

  function bindCcInputs() {
    Object.keys(CC_FIELDS).forEach(function (key) {
      var el = document.getElementById(CC_FIELDS[key]);
      if (!el) return;
      el.addEventListener('input', function () {
        if (applying) return;
        var patch = {};
        patch[key] = el.value;
        set(patch, { skipPersist: false });
      });
    });
  }

  function bindCsPanel() {
    var panel = document.getElementById('cs-vars-panel');
    if (!panel) return;
    if (panel.dataset.varsDelegated === '1') return;
    panel.dataset.varsDelegated = '1';
    panel.addEventListener('input', function (e) {
      var inp = e.target && e.target.closest ? e.target.closest('input[data-cs-var]') : null;
      if (!inp || applying) return;
      var key = inp.getAttribute('data-cs-var');
      var patch = {};
      patch[key] = inp.value;
      set(patch, { skipPersist: false });
    });
  }

  function bindTerminalInputs() {
    if (document.body.dataset.terminalVarsBound === '1') return;
    document.body.dataset.terminalVarsBound = '1';
    ['input-ip', 'input-user', 'input-pass'].forEach(function (id) {
      var el = document.getElementById(id);
      if (!el) return;
      el.addEventListener('input', function () {
        if (applying) return;
        applyTerminalToVars();
        schedulePersist();
      });
    });
  }

  function syncFromState(s) {
    if (!s) return;
    store = {};
    if (s.cheatsheet_vars) {
      Object.keys(s.cheatsheet_vars).forEach(function (k) {
        store[k] = s.cheatsheet_vars[k];
      });
      if (typeof state !== 'undefined') state.cheatsheet_vars = Object.assign({}, s.cheatsheet_vars);
    }
    if (s.meta && s.meta.workspace) store.workspace = String(s.meta.workspace);
    applyToViews();
    updateReadinessUI();
  }

  function updateReadinessUI() {
    var r = readiness();
    if (typeof state !== 'undefined') state.workspace_readiness = r;

    var scanBtn = document.getElementById('btn-scan');
    var authBtn = document.getElementById('btn-auth');
    if (scanBtn) scanBtn.disabled = false;
    if (authBtn) authBtn.disabled = !r.auth_ready;

    document.querySelectorAll('button.run').forEach(function (btn) {
      if (btn.hasAttribute('data-requires-auth')) {
        btn.disabled = !r.auth_ready;
        btn.title = r.auth_ready ? '' : 'Fill username + password/hash in vars first';
      } else {
        btn.disabled = !r.scan_ready;
        btn.title = r.scan_ready ? '' : 'Set DC IP in vars first';
      }
    });

    if (typeof CheatsheetView !== 'undefined' && CheatsheetView.renderCommands) {
      CheatsheetView.renderCommands();
    }
  }

  function toSubstExtra() {
    var v = get();
    return {
      domain: v.DOMAIN || '',
      dc: v.DC_IP || '',
      user: v.USERNAME || '',
      pass: v.PASSWORD || '',
      password: v.PASSWORD || '',
      hash: v.NTLM_HASH || '',
      workspace: v.workspace || '',
      attackerIp: v.ATTACKER_IP || '',
      caName: v.CA_NAME || '',
      template: v.TEMPLATE || ''
    };
  }

  function connectFromTerminal() {
    applyTerminalToVars();
    var v = get();
    var r = readiness();
    if (!r.auth_ready) {
      if (typeof termLogSemantic === 'function') {
        termLogSemantic('Need DC IP, username, and password (or hash in vars)', 'error');
      }
      return Promise.resolve();
    }
    return fetch('/api/workspace/connect', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        workspace_vars: v,
        DC_IP: v.DC_IP,
        USERNAME: v.USERNAME,
        PASSWORD: v.PASSWORD,
        NTLM_HASH: v.NTLM_HASH,
        username: v.USERNAME,
        password: v.PASSWORD,
        host: v.DC_IP
      })
    }).then(function (resp) {
      return resp.json().then(function (data) {
        if (!resp.ok) return Object.assign({ error: data.error || ('HTTP ' + resp.status) }, data);
        return data;
      });
    });
  }

  return {
    get: get,
    set: set,
    readiness: readiness,
    syncFromState: syncFromState,
    applyToViews: applyToViews,
    bindCcInputs: bindCcInputs,
    bindCsPanel: bindCsPanel,
    bindTerminalInputs: bindTerminalInputs,
    syncTerminalFromVars: syncTerminalFromVars,
    applyTerminalToVars: applyTerminalToVars,
    persistNow: persistNow,
    updateReadinessUI: updateReadinessUI,
    connectFromTerminal: connectFromTerminal,
    toSubstExtra: toSubstExtra
  };
})();
"""
