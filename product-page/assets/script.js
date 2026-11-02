/*
 * ToolKit interactive simulator — application logic.
 * Pure client-side demo. No network calls, no execution of real commands.
 * Depends on assets/data.js being loaded first.
 */
(function () {
  'use strict';

  /* ---------------------------------------------------------- helpers --- */

  function escapeHtml(str) {
    return String(str == null ? '' : str)
      .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;').replace(/'/g, '&#39;');
  }

  function el(tag, attrs, children) {
    const node = document.createElement(tag);
    if (attrs) Object.keys(attrs).forEach((k) => {
      if (k === 'class') node.className = attrs[k];
      else if (k === 'html') node.innerHTML = attrs[k];
      else node.setAttribute(k, attrs[k]);
    });
    (children || []).forEach((c) => node.appendChild(typeof c === 'string' ? document.createTextNode(c) : c));
    return node;
  }

  const NICE_NAMES = {
    splunk: 'Splunk', wazuh: 'Wazuh', sentinel: 'Microsoft Sentinel', qradar: 'IBM QRadar', elastic: 'Elastic SIEM',
    crowdstrike: 'CrowdStrike', sentinelone: 'SentinelOne', defender: 'Microsoft Defender',
    nmap: 'nmap', paloalto: 'Palo Alto', fortinet: 'Fortinet', cisco: 'Cisco', opnsense: 'OPNsense',
    zap: 'OWASP ZAP', burpsuite: 'Burp Suite', nuclei: 'Nuclei', postman: 'Postman',
    iacauditor: 'IaC Auditor', guardduty: 'AWS GuardDuty', securityhub: 'AWS Security Hub',
    prismacloud: 'Prisma Cloud', mandiant: 'Mandiant',
    trivy: 'Trivy', tenable: 'Tenable (Nessus)', qualys: 'Qualys', rapid7: 'Rapid7', openvas: 'OpenVAS',
    llmriskscanner: 'LLM Risk Scanner', darktrace: 'Darktrace', vectra: 'Vectra',
  };
  const niceName = (n) => NICE_NAMES[n] || n;

  function getTool(moduleKey, toolName) {
    return (TOOLS[moduleKey] || []).find((t) => t.name === toolName);
  }

  function firstImplemented(moduleKey) {
    return (TOOLS[moduleKey] || []).find((t) => t.status === 'implemented');
  }

  function classifyTarget(target) {
    if (!target) return 'Unknown';
    if (/^\d{1,3}(\.\d{1,3}){3}$/.test(target)) return 'IP Address';
    if (/^[a-zA-Z][a-zA-Z0-9+.-]*:\/\//.test(target)) return 'URL';
    if (target.includes('/')) return 'Network Range (CIDR)';
    return 'Hostname';
  }

  function extractHost(target) {
    let t = (target || '').trim();
    if (t.includes('://')) {
      try { return new URL(t).hostname; } catch (e) { /* fallthrough */ }
    }
    let host = t.split('/')[0];
    const colonCount = (host.match(/:/g) || []).length;
    if (colonCount === 1) host = host.split(':')[0];
    return host || null;
  }

  function isPrivateHost(host) {
    if (!host) return false;
    if (host.toLowerCase() === 'localhost' || host === '::1') return true;
    const m = host.match(/^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/);
    if (!m) return 'unknown'; // not a literal IP — can't verify client-side without DNS
    const o = [+m[1], +m[2], +m[3], +m[4]];
    return PRIVATE_RANGES.some((r) => r.test(o));
  }

  /* ------------------------------------------------------- nav & chrome - */

  function initNav() {
    const toggle = document.getElementById('nav-toggle');
    const nav = document.getElementById('main-nav');
    toggle.addEventListener('click', () => {
      const open = nav.classList.toggle('open');
      toggle.setAttribute('aria-expanded', String(open));
    });
    document.querySelectorAll('.nav-link').forEach((link) => {
      link.addEventListener('click', () => nav.classList.remove('open'));
    });

    const links = Array.from(document.querySelectorAll('.nav-link'));
    const sections = links.map((l) => document.querySelector(l.getAttribute('href'))).filter(Boolean);
    const io = new IntersectionObserver((entries) => {
      entries.forEach((entry) => {
        if (entry.isIntersecting) {
          const id = '#' + entry.target.id;
          links.forEach((l) => l.classList.toggle('active', l.getAttribute('href') === id));
        }
      });
    }, { rootMargin: '-40% 0px -50% 0px' });
    sections.forEach((s) => io.observe(s));

    const toTop = document.getElementById('to-top');
    window.addEventListener('scroll', () => {
      toTop.classList.toggle('visible', window.scrollY > 600);
    });
    toTop.addEventListener('click', () => window.scrollTo({ top: 0, behavior: 'smooth' }));
  }

  function initReveal() {
    const items = document.querySelectorAll('.reveal');
    const io = new IntersectionObserver((entries) => {
      entries.forEach((entry) => {
        if (entry.isIntersecting) {
          entry.target.classList.add('in-view');
          io.unobserve(entry.target);
        }
      });
    }, { threshold: 0.12 });
    items.forEach((i) => io.observe(i));
  }

  function initHeroTyper() {
    const target = document.getElementById('hero-typer');
    const demos = [
      { cmd: '$ toolkit --version', out: 'ToolKit v1.0.0\nStatus: Operational' },
      { cmd: '$ toolkit status', out: 'Checking System Dependencies...\n\ndocker      ✓   24.0.6\nterraform   ✓   1.7.0\nkubectl     ✗   N/A\nansible     ✗   N/A' },
      { cmd: '$ toolkit list-tools cloudsec', out: 'iacauditor   Open Source   implemented          Static Terraform/Compose scanner\nguardduty    Cloud         catalog-only          AWS threat detection' },
      { cmd: '$ toolkit scan cloudsec iacauditor --target labs/', out: 'Scanned 2 file(s), 0 finding(s)\n✓ Scan completed successfully!' },
    ];
    let i = 0;
    function typeLine(text, cb) {
      let j = 0;
      target.textContent = '';
      (function step() {
        target.textContent += text[j];
        j++;
        if (j < text.length) setTimeout(step, 18);
        else setTimeout(cb, 300);
      })();
    }
    function run() {
      const demo = demos[i % demos.length];
      typeLine(demo.cmd, () => {
        target.textContent += '\n' + demo.out;
        setTimeout(() => { i++; run(); }, 2400);
      });
    }
    run();
  }

  /* -------------------------------------------------- explorer section - */

  let explorerModule = 'cloudsec';

  function renderDomainTabs() {
    const wrap = document.getElementById('domain-tabs');
    wrap.innerHTML = '';
    MODULES.forEach((m) => {
      const btn = el('button', { class: 'domain-tab' + (m.key === explorerModule ? ' active' : ''), role: 'tab' }, [m.label]);
      btn.addEventListener('click', () => { explorerModule = m.key; renderDomainTabs(); renderToolGrid(); document.getElementById('tool-detail').hidden = true; });
      wrap.appendChild(btn);
    });
  }

  function renderToolGrid() {
    const grid = document.getElementById('tool-grid');
    grid.innerHTML = '';
    (TOOLS[explorerModule] || []).forEach((tool) => {
      const implemented = tool.status === 'implemented';
      const card = el('div', { class: 'tool-card' + (implemented ? ' is-implemented' : ' is-catalog') });
      card.appendChild(el('div', { class: 'tool-card-top' }, [
        el('span', { class: 'legend-dot ' + (implemented ? 'legend-implemented' : 'legend-catalog') }),
        el('strong', {}, [niceName(tool.name)]),
      ]));
      card.appendChild(el('p', { class: 'tool-card-desc' }, [tool.description]));
      card.appendChild(el('span', { class: 'tool-card-status' }, [implemented ? 'Implemented' : 'Catalog-only']));
      if (implemented) {
        card.addEventListener('click', () => showToolDetail(tool));
      } else {
        card.title = 'Catalog-only — requires the vendor\'s own commercial account. Not runnable via ToolKit.';
      }
      grid.appendChild(card);
    });
  }

  function opBadge(tool, op) {
    const info = tool.operations[op];
    if (!info || info.supported === false) return el('span', { class: 'op-pill op-no' }, [op, ' ✕']);
    if (info.supported === 'simulate-only') return el('span', { class: 'op-pill op-partial' }, [op, ' (simulate only)']);
    return el('span', { class: 'op-pill op-yes' }, [op, ' ✓']);
  }

  function showToolDetail(tool) {
    const detail = document.getElementById('tool-detail');
    detail.hidden = false;
    detail.innerHTML = '';
    detail.appendChild(el('h3', {}, [niceName(tool.name), ' — supported operations']));
    const pills = el('div', { class: 'op-pill-row' });
    ['deploy', 'scan', 'report', 'open'].forEach((op) => pills.appendChild(opBadge(tool, op)));
    detail.appendChild(pills);

    const notes = el('ul', { class: 'tool-notes' });
    ['deploy', 'scan', 'report', 'open'].forEach((op) => {
      const info = tool.operations[op];
      if (info && info.note) {
        notes.appendChild(el('li', {}, [el('strong', {}, [op + ': ']), info.note]));
      }
    });
    detail.appendChild(notes);

    const btn = el('button', { class: 'btn btn-primary btn-small' }, ['Load into command console ↓']);
    btn.addEventListener('click', () => {
      consoleState.module = explorerModule;
      consoleState.tool = tool.name;
      const firstOp = ['scan', 'deploy', 'report', 'open'].find((o) => tool.operations[o] && tool.operations[o].supported !== false) || 'scan';
      consoleState.op = firstOp;
      resetFlagsForToolOp();
      renderConsole();
      document.getElementById('console').scrollIntoView({ behavior: 'smooth', block: 'start' });
    });
    detail.appendChild(btn);
  }

  /* --------------------------------------------------------- console --- */

  const consoleState = { module: 'cloudsec', tool: 'iacauditor', op: 'scan', flags: {} };

  function defaultFlags(tool, op) {
    const f = {};
    if (op === 'deploy') {
      f.environment = tool.defaultEnvironment || 'docker';
      f.dryRun = false; f.skipValidation = false; f.autoApprove = false;
      f.region = 'us-east-1'; f.instanceType = '';
    } else if (op === 'scan') {
      f.target = tool.targetPlaceholder || '';
      f.scanType = 'quick'; f.ports = ''; f.timeout = 300;
      f.simulate = !!tool.simulateOnly;
      f.scenario = 'all';
      f.allowUnsafe = false;
    } else if (op === 'report') {
      f.format = 'html'; f.outputDir = './reports'; f.severityFilter = 'all'; f.priorResult = true;
    } else if (op === 'open') {
      f.host = ''; f.port = ''; f.printUrl = false;
    }
    return f;
  }

  function resetFlagsForToolOp() {
    const tool = getTool(consoleState.module, consoleState.tool);
    consoleState.flags = defaultFlags(tool, consoleState.op);
  }

  function populateModuleSelect() {
    const sel = document.getElementById('sel-module');
    sel.innerHTML = '';
    MODULES.forEach((m) => sel.appendChild(el('option', { value: m.key }, [m.label + ' — ' + m.full])));
    sel.value = consoleState.module;
    sel.addEventListener('change', () => {
      consoleState.module = sel.value;
      const t = firstImplemented(consoleState.module);
      consoleState.tool = t ? t.name : (TOOLS[consoleState.module][0] || {}).name;
      const tool = getTool(consoleState.module, consoleState.tool);
      consoleState.op = ['scan', 'deploy', 'report', 'open'].find((o) => tool && tool.operations[o] && tool.operations[o].supported !== false) || 'scan';
      resetFlagsForToolOp();
      renderConsole();
    });
  }

  function populateToolSelect() {
    const sel = document.getElementById('sel-tool');
    sel.innerHTML = '';
    (TOOLS[consoleState.module] || []).forEach((t) => {
      const opt = el('option', { value: t.name }, [niceName(t.name) + (t.status === 'catalog' ? ' (catalog-only — not runnable)' : '')]);
      if (t.status === 'catalog') opt.disabled = true;
      sel.appendChild(opt);
    });
    sel.value = consoleState.tool;
    sel.onchange = () => {
      consoleState.tool = sel.value;
      const tool = getTool(consoleState.module, consoleState.tool);
      consoleState.op = ['scan', 'deploy', 'report', 'open'].find((o) => tool.operations[o] && tool.operations[o].supported !== false) || 'scan';
      resetFlagsForToolOp();
      renderConsole();
    };
  }

  function renderOpTabs(tool) {
    const wrap = document.getElementById('op-tabs');
    wrap.innerHTML = '';
    ['deploy', 'scan', 'report', 'open'].forEach((op) => {
      const info = tool.operations[op];
      const disabled = !info || info.supported === false;
      const btn = el('button', { class: 'op-tab' + (op === consoleState.op ? ' active' : '') + (disabled ? ' disabled' : '') }, [op]);
      if (disabled) {
        btn.disabled = true;
        btn.title = info ? info.note : 'Not supported by this tool.';
      } else {
        btn.addEventListener('click', () => {
          consoleState.op = op;
          resetFlagsForToolOp();
          renderConsole();
        });
      }
      wrap.appendChild(btn);
    });
  }

  function field(labelText, inputHtml, note) {
    const wrap = el('div', { class: 'flag-field' });
    wrap.appendChild(el('label', {}, [labelText]));
    wrap.appendChild(el('div', { html: inputHtml }));
    if (note) wrap.appendChild(el('p', { class: 'flag-note' }, [note]));
    return wrap;
  }

  function renderFlagForm() {
    const tool = getTool(consoleState.module, consoleState.tool);
    const form = document.getElementById('flag-form');
    form.innerHTML = '';
    const f = consoleState.flags;
    const op = consoleState.op;

    if (op === 'deploy') {
      if (tool.environments && tool.environments.length > 1) {
        const opts = tool.environments.map((e) => `<option value="${e}" ${e === f.environment ? 'selected' : ''}>${e}</option>`).join('');
        form.appendChild(field('--environment', `<select data-field="environment">${opts}</select>`, tool.environmentNote || null));
      } else {
        form.appendChild(field('--environment', `<input type="text" value="${tool.environments ? tool.environments[0] : 'docker'}" disabled>`,
          'Fixed — ' + (tool.operations.deploy.note || '')));
      }
      form.appendChild(field('', `<label class="checkbox-label"><input type="checkbox" data-field="dryRun" ${f.dryRun ? 'checked' : ''}> --dry-run</label>`));
      form.appendChild(field('', `<label class="checkbox-label"><input type="checkbox" data-field="skipValidation" ${f.skipValidation ? 'checked' : ''}> --skip-validation</label>`));
      form.appendChild(field('', `<label class="checkbox-label"><input type="checkbox" data-field="autoApprove" ${f.autoApprove ? 'checked' : ''}> --auto-approve</label>`));
      if (f.environment === 'aws') {
        form.appendChild(field('--region', `<input type="text" data-field="region" value="${escapeHtml(f.region)}">`));
        form.appendChild(field('--instance-type', `<input type="text" data-field="instanceType" placeholder="t3.xlarge" value="${escapeHtml(f.instanceType)}">`));
      }
    }

    if (op === 'scan') {
      form.appendChild(field('--target' + (tool.targetIgnored ? ' (required by CLI, ignored by this module)' : ''),
        `<input type="text" data-field="target" value="${escapeHtml(f.target)}" placeholder="${escapeHtml(tool.targetPlaceholder || '')}">`));

      let scanTypeNote = null;
      if (tool.scanTypeIgnored) scanTypeNote = 'Accepted by the CLI but not read by this module — scans run the same regardless.';
      else if (tool.scanTypeMap) scanTypeNote = 'nmap flags: ' + JSON.stringify(tool.scanTypeMap).replace(/[{}"]/g, '');
      const stOpts = SCAN_TYPES.map((s) => `<option value="${s}" ${s === f.scanType ? 'selected' : ''}>${s}</option>`).join('');
      form.appendChild(field('--scan-type', `<select data-field="scanType">${stOpts}</select>`,
        tool.scanTypeMap ? (tool.scanTypeMap[f.scanType] ? 'Maps to: ' + tool.scanTypeMap[f.scanType] : scanTypeNote) : scanTypeNote));

      if (tool.portsRelevant) {
        form.appendChild(field('--ports', `<input type="text" data-field="ports" placeholder="1-1000 or 22,80,443" value="${escapeHtml(f.ports)}">`));
      }

      form.appendChild(field('--timeout (seconds)', `<input type="number" data-field="timeout" value="${f.timeout}">`,
        tool.timeoutIgnored ? 'Accepted by the CLI but this module uses its own fixed polling timeout.' : null));

      if (tool.simulateOnly) {
        form.appendChild(field('', `<label class="checkbox-label"><input type="checkbox" checked disabled> --simulate (forced)</label>`,
          'Splunk has no scan.py — only simulate.py. The CLI would fail to load a plain "scan" operation, so --simulate is always on.'));
        const scenOpts = (tool.scenarios || []).map((s) => `<option value="${s.key}" ${s.key === f.scenario ? 'selected' : ''}>${s.label}</option>`).join('');
        form.appendChild(field('--scenario', `<select data-field="scenario">${scenOpts}</select>`));
      } else {
        form.appendChild(field('', `<label class="checkbox-label"><input type="checkbox" data-field="simulate" disabled> --simulate</label>`,
          'Only Splunk implements a simulate operation — selecting this for another tool would fail to import a simulate.py module.'));
      }

      if (tool.authEnforced === true || tool.authEnforced === 'image-only') {
        form.appendChild(field('', `<label class="checkbox-label"><input type="checkbox" data-field="allowUnsafe" ${f.allowUnsafe ? 'checked' : ''}> --i-have-authorization</label>`,
          tool.authEnforced === 'image-only'
            ? 'Only enforced when scanning a remote image reference — a local filesystem target (the default here) is not gated.'
            : 'Required to target anything outside loopback/RFC1918 ranges. See the authorization checker in the Security Model section.'));
      }
    }

    if (op === 'report') {
      const fmtOpts = ['html', 'markdown'].map((x) => `<option value="${x}" ${x === f.format ? 'selected' : ''}>${x}</option>`).join('');
      form.appendChild(field('--format', `<select data-field="format">${fmtOpts}</select>`));
      form.appendChild(field('--output-dir', `<input type="text" data-field="outputDir" value="${escapeHtml(f.outputDir)}">`));
      const sevOpts = SEVERITY_FILTERS.map((x) => `<option value="${x}" ${x === f.severityFilter ? 'selected' : ''}>${x}</option>`).join('');
      form.appendChild(field('--severity-filter', `<select data-field="severityFilter">${sevOpts}</select>`));
      form.appendChild(field('', `<label class="checkbox-label"><input type="checkbox" data-field="priorResult" ${f.priorResult ? 'checked' : ''}> Assume a prior scan/deploy result exists</label>`,
        'Uncheck to see the real failure path when no .toolkit_state/ result is on disk yet.'));
    }

    if (op === 'open') {
      if (tool.dashboardUrl) {
        form.appendChild(field('Default dashboard URL', `<input type="text" value="${escapeHtml(tool.dashboardUrl)}" disabled>`,
          `From DASHBOARD_URLS['${tool.name}'] in toolkit/open_dashboard.py.`));
      } else {
        form.appendChild(field('Default dashboard URL', `<input type="text" value="(none configured)" disabled>`,
          `${niceName(tool.name)} has no entry in DASHBOARD_URLS — running this without --host prints "No default URL configured for ${tool.name}".`));
      }
      form.appendChild(field('--host', `<input type="text" data-field="host" placeholder="192.168.1.10" value="${escapeHtml(f.host)}">`));
      form.appendChild(field('--port', `<input type="number" data-field="port" value="${escapeHtml(f.port)}">`));
      form.appendChild(field('', `<label class="checkbox-label"><input type="checkbox" data-field="printUrl" ${f.printUrl ? 'checked' : ''}> --print-url</label>`));
    }

    form.querySelectorAll('[data-field]').forEach((input) => {
      input.addEventListener('input', onFlagChange);
      input.addEventListener('change', onFlagChange);
    });
  }

  function onFlagChange(e) {
    const key = e.target.getAttribute('data-field');
    let val;
    if (e.target.type === 'checkbox') val = e.target.checked;
    else if (e.target.type === 'number') val = e.target.value === '' ? '' : Number(e.target.value);
    else val = e.target.value;
    consoleState.flags[key] = val;
    const needsFullRerender = key === 'environment' || key === 'simulate';
    if (needsFullRerender) renderFlagForm();
    renderGeneratedCommand();
    document.getElementById('sim-panel').hidden = true;
  }

  function quoteIfNeeded(v) {
    const s = String(v == null ? '' : v);
    return /\s/.test(s) ? `"${s}"` : s;
  }

  function buildCommandParts() {
    const tool = getTool(consoleState.module, consoleState.tool);
    const f = consoleState.flags;
    const op = consoleState.op;
    const parts = ['toolkit', op, consoleState.module, tool.name];

    if (op === 'deploy') {
      if (tool.environments && tool.environments.length > 1 && f.environment && f.environment !== (tool.defaultEnvironment || 'docker')) {
        parts.push('--environment', f.environment);
      }
      if (f.dryRun) parts.push('--dry-run');
      if (f.skipValidation) parts.push('--skip-validation');
      if (f.autoApprove) parts.push('--auto-approve');
      if (f.environment === 'aws') {
        if (f.region && f.region !== 'us-east-1') parts.push('--region', f.region);
        if (f.instanceType) parts.push('--instance-type', quoteIfNeeded(f.instanceType));
      }
    }

    if (op === 'scan') {
      parts.push('--target', quoteIfNeeded(f.target || tool.targetPlaceholder || '<target>'));
      if (f.scanType && f.scanType !== 'quick') parts.push('--scan-type', f.scanType);
      if (f.ports) parts.push('--ports', f.ports);
      if (f.timeout && Number(f.timeout) !== 300) parts.push('--timeout', f.timeout);
      const simulateOn = tool.simulateOnly || f.simulate;
      if (simulateOn) {
        parts.push('--simulate');
        if (tool.scenarios && f.scenario && f.scenario !== 'all') parts.push('--scenario', f.scenario);
      }
      if (f.allowUnsafe) parts.push('--i-have-authorization');
    }

    if (op === 'report') {
      if (f.format && f.format !== 'html') parts.push('--format', f.format);
      if (f.outputDir && f.outputDir !== './reports') parts.push('--output-dir', quoteIfNeeded(f.outputDir));
      if (f.severityFilter && f.severityFilter !== 'all') parts.push('--severity-filter', f.severityFilter);
    }

    if (op === 'open') {
      if (f.host) parts.push('--host', f.host);
      if (f.port) parts.push('--port', f.port);
      if (f.printUrl) parts.push('--print-url');
    }

    return parts;
  }

  function renderGeneratedCommand() {
    const parts = buildCommandParts();
    document.getElementById('generated-command').textContent = parts.join(' ');
    syncReportsWithConsole();
  }

  /* ------------------------------------------------- simulated output --- */

  function line(cls, text) { return `<span class="${cls}">${text}</span>`; }

  function panel(title, lines) {
    const width = Math.max(title.length + 4, ...lines.map((l) => l.replace(/<[^>]+>/g, '').length)) + 2;
    const top = '╭─ ' + title + ' ' + '─'.repeat(Math.max(0, width - title.length - 3)) + '╮';
    const bottom = '╰' + '─'.repeat(width) + '╯';
    const body = lines.map((l) => '│ ' + l).join('\n');
    return `<span class="dim">${top}</span>\n${body}\n<span class="dim">${bottom}</span>`;
  }

  function buildSimulatedOutput() {
    const tool = getTool(consoleState.module, consoleState.tool);
    const f = consoleState.flags;
    const op = consoleState.op;
    const out = [];

    if (op === 'deploy') {
      const env = (tool.environments && tool.environments.length > 1) ? f.environment : (tool.environments ? tool.environments[0] : 'docker');
      out.push(panel('Deployment Configuration', [
        line('ok', 'Deploying ' + tool.name.toUpperCase()),
        `Module: ${consoleState.module.toUpperCase()}`,
        `Environment: ${env}`,
        `Region: ${f.region || 'us-east-1'}`,
      ]));
      if (!f.skipValidation) {
        out.push('\nValidating configuration...');
        out.push(line('ok', '✓ Configuration valid'));
      }
      if (env === 'aws' || env === 'kubernetes') {
        out.push('\nChecking dependencies...');
        out.push(line('ok', '✓ All dependencies satisfied'));
      }
      if (!f.autoApprove && !f.dryRun) {
        out.push('\nProceed with deployment? [y/N]: y');
      }
      if (f.dryRun) out.push(line('warn', '\nDRY RUN MODE - No changes will be made'));
      out.push(`\nDeploying ${tool.name}...`);

      if (tool.name === 'zap' && env !== 'docker') {
        out.push(line('err', `Unsupported environment for ZAP: ${env} (only 'docker' is implemented)`));
        out.push(line('err', '\n✗ Deployment failed'));
        out.push(line('warn', 'Check logs for more details'));
      } else {
        out.push(line('ok', `\n✓ ${tool.name} deployed successfully!`));
        if (tool.dashboardUrl) out.push(`\nTo access the dashboard, run: toolkit open ${consoleState.module} ${tool.name}`);
      }
      return out.join('\n');
    }

    if (op === 'scan') {
      const simulateOn = tool.simulateOnly || f.simulate;
      const operation = simulateOn ? 'simulate' : 'scan';

      const target = f.target || tool.targetPlaceholder || '';
      const targetType = classifyTarget(target);
      const panelLines = [
        `Module: ${consoleState.module.toUpperCase()}`,
        `Tool: ${tool.name}`,
        `Target: ${escapeHtml(target)}`,
        `Target Type: ${targetType}`,
        `Scan Type: ${f.scanType}`,
      ];
      if (f.ports) panelLines.push(`Ports: ${f.ports}`);
      panelLines.push(`Timeout: ${f.timeout}s`);
      if (simulateOn) panelLines.push('Mode: Attack Simulation');
      out.push(panel('Scan Configuration', panelLines));
      out.push(`\nStarting ${operation}...`);

      if (tool.authEnforced === true) {
        const host = extractHost(target);
        const priv = isPrivateHost(host);
        if (priv === false && !f.allowUnsafe) {
          out.push(line('err', `\n'${escapeHtml(target)}' is outside private/loopback ranges. Active scans and attack `
            + `simulations must be restricted to targets you are explicitly authorized to test. Re-run with `
            + `--i-have-authorization only if you own this target or hold written permission to test it.`));
          out.push(line('err', `\n✗ ${cap(operation)} failed`));
          out.push(line('warn', 'Check logs for more details'));
          return out.join('\n');
        }
        if (priv === false && f.allowUnsafe) {
          out.push(line('warn', `\nProceeding against '${escapeHtml(target)}', which is outside private/loopback ranges, `
            + `because --i-have-authorization was set. Only test systems you are explicitly authorized to assess.`));
        }
      }

      out.push('\n' + toolScanBody(tool, f, target));
      out.push(line('ok', `\n✓ ${cap(operation)} completed successfully!`));
      out.push(`\nTo generate a detailed report, run:\ntoolkit report ${consoleState.module} ${tool.name}`);
      return out.join('\n');
    }

    if (op === 'report') {
      const ext = f.format === 'markdown' ? 'md' : 'html';
      const path = `${f.outputDir || './reports'}/${tool.name}_security_report_<timestamp>.${ext}`;
      out.push(panel('Report Configuration', [
        `Generating Report for ${tool.name.toUpperCase()}`,
        `Module: ${consoleState.module.toUpperCase()}`,
        `Format: ${(f.format || 'html').toUpperCase()}`,
        `Output: ${path}`,
      ]));
      out.push('\nGenerating report...');
      if (!f.priorResult) {
        out.push(line('err', '\n' + tool.noPriorMessage));
        out.push(line('err', '\n✗ Report generation failed'));
        out.push(line('warn', 'Check logs for more details'));
      } else {
        out.push(line('ok', '\n✓ Report generated successfully!'));
        out.push(`Report saved to: ${path}`);
        out.push(`File size: ${(1.4 + (tool.name.length % 5) * 0.3).toFixed(2)} KB`);
      }
      return out.join('\n');
    }

    if (op === 'open') {
      let url = tool.dashboardUrl || null;
      if (f.host) {
        const proto = f.port === 443 ? 'https' : 'http';
        url = `${proto}://${f.host}` + (f.port && f.port !== 80 && f.port !== 443 ? `:${f.port}` : '');
      }
      if (!url) {
        out.push(line('warn', `No default URL configured for ${tool.name}`));
        out.push(line('warn', 'Use --host and --port to specify custom URL'));
        return out.join('\n');
      }
      out.push(panel('Dashboard Access', [
        `Opening ${tool.name.toUpperCase()} Dashboard`,
        `Module: ${consoleState.module.toUpperCase()}`,
        `URL: ${escapeHtml(url)}`,
      ]));
      if (f.printUrl) {
        out.push('\n' + url);
      } else {
        out.push('\nOpening in browser...');
        out.push(line('ok', '✓ Dashboard opened'));
      }
      return out.join('\n');
    }

    return '';
  }

  function cap(s) { return s.charAt(0).toUpperCase() + s.slice(1); }

  function toolScanBody(tool, f, target) {
    if (tool.name === 'nmap') {
      const flags = (tool.scanTypeMap[f.scanType] || tool.scanTypeMap.quick).split(' — ')[0].split(' (')[0];
      return `Running: nmap ${flags} -oX /tmp/scan.xml ${target}\nScan complete: 2 host(s), 3 open port finding(s).`;
    }
    if (tool.name === 'trivy') {
      const sev = tool.scanTypeMap[f.scanType] || tool.scanTypeMap.quick;
      return `Running: trivy fs --format json --severity ${sev} --output /tmp/trivy.json ${target}\nScan complete: 2 vulnerabilit(y/ies) found across ${target}.`;
    }
    if (tool.name === 'zap') {
      const lines = [`Spidering ${target}`];
      if (f.scanType !== 'quick') lines.push(`Running active scan against ${target}`);
      lines.push(`Scan complete: ${f.scanType !== 'quick' ? 3 : 2} finding(s).`);
      return lines.join('\n');
    }
    if (tool.name === 'iacauditor') {
      return `Scanned 2 file(s), 2 finding(s)`;
    }
    if (tool.name === 'llmriskscanner') {
      return `Scanned 1 file(s), 2 finding(s)`;
    }
    if (tool.name === 'wazuh') {
      const findings = tool.sampleFindings || [];
      const running = findings.filter((x) => x.severity === 'info').length;
      return `Wazuh health check: ${running}/${findings.length} containers running\n` +
        findings.map((x) => `  ${x.title}: ${x.severity === 'info' ? 'running' : 'exited'}`).join('\n');
    }
    if (tool.name === 'splunk') {
      const scenarios = f.scenario === 'all' ? ['brute_force', 'lateral_movement', 'data_exfiltration', 'privilege_escalation', 'persistence'] : [f.scenario];
      const lines = scenarios.map((s) => `Simulating: ${s}`);
      lines.push(`Simulation complete. Generated events across ${scenarios.length} scenario(s).`);
      return lines.join('\n');
    }
    return 'Scan complete.';
  }

  function initConsole() {
    resetFlagsForToolOp();
    populateModuleSelect();
    populateToolSelect();
    renderConsole();

    document.getElementById('copy-command').addEventListener('click', () => {
      const text = document.getElementById('generated-command').textContent;
      const feedback = document.getElementById('copy-feedback');
      const done = () => { feedback.textContent = 'Copied ✓'; setTimeout(() => { feedback.textContent = ''; }, 1800); };
      if (navigator.clipboard && navigator.clipboard.writeText) {
        navigator.clipboard.writeText(text).then(done).catch(() => { feedback.textContent = 'Copy failed — select and copy manually.'; });
      } else {
        feedback.textContent = 'Copy not supported — select and copy manually.';
      }
    });

    document.getElementById('run-simulated').addEventListener('click', () => {
      const panelEl = document.getElementById('sim-panel');
      const body = document.getElementById('sim-body');
      body.innerHTML = buildSimulatedOutput();
      panelEl.hidden = !panelEl.hidden ? panelEl.hidden : false;
      panelEl.hidden = false;
      panelEl.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
    });
  }

  function renderConsole() {
    const tool = getTool(consoleState.module, consoleState.tool);
    document.getElementById('sel-module').value = consoleState.module;
    populateToolSelect();
    renderOpTabs(tool);
    renderFlagForm();
    renderGeneratedCommand();
    document.getElementById('sim-panel').hidden = true;
  }

  function loadPreset(preset) {
    consoleState.module = preset.module;
    consoleState.tool = preset.tool;
    consoleState.op = preset.op;
    const tool = getTool(preset.module, preset.tool);
    consoleState.flags = Object.assign(defaultFlags(tool, preset.op), preset.flags);
    renderConsole();
    document.getElementById('console').scrollIntoView({ behavior: 'smooth', block: 'start' });
  }

  function renderPresets() {
    const row = document.getElementById('preset-row');
    row.innerHTML = '';
    row.appendChild(el('span', { class: 'preset-label' }, ['Quick start:']));
    PRESETS.forEach((p) => {
      const btn = el('button', { class: 'preset-chip' }, [p.label]);
      btn.addEventListener('click', () => loadPreset(p));
      row.appendChild(btn);
    });
  }

  /* --------------------------------------------------- sample reports --- */

  let reportFormat = 'html';

  function reportFindingsFor(tool, flags) {
    if (tool.sampleFindingsFn) {
      const arg1 = flags && (flags.scenario || flags.scanType);
      try { return tool.sampleFindingsFn(arg1, flags && flags.scenario); } catch (e) { return tool.sampleFindingsFn(); }
    }
    return tool.sampleFindings || [];
  }

  function reportSummaryFor(tool, flags) {
    if (!tool.summaryFn) return 'No summary available.';
    const target = (flags && flags.target) || tool.targetPlaceholder || '.';
    const scanType = (flags && flags.scanType) || 'quick';
    const sev = (tool.scanTypeMap && tool.scanTypeMap[scanType]) || 'CRITICAL,HIGH';
    if (tool.name === 'splunk') return tool.summaryFn(target, flags && flags.scenario || 'brute_force');
    if (tool.name === 'trivy') return tool.summaryFn(target, scanType, sev);
    return tool.summaryFn(target, scanType);
  }

  const HTML_REPORT_STYLE = `
    body { font-family: -apple-system, Helvetica, Arial, sans-serif; margin: 40px; color: #1a1a1a; background:#fff; }
    h1 { margin: 0; }
    .header { background: #1b2838; color: #fff; padding: 20px 24px; border-radius: 6px; }
    .meta { color: #cbd5e1; font-size: 0.9em; margin-top: 6px; }
    .section { margin: 24px 0; padding: 20px; border: 1px solid #e2e8f0; border-radius: 6px; }
    .finding { margin: 12px 0; padding: 12px 14px; border-radius: 4px; border-left: 4px solid #94a3b8; background: #f8fafc; }
    .critical { background: #fee2e2; border-left-color: #dc2626; }
    .high { background: #ffedd5; border-left-color: #ea580c; }
    .medium { background: #fef3c7; border-left-color: #d97706; }
    .low { background: #dcfce7; border-left-color: #16a34a; }
    .info { background: #e0f2fe; border-left-color: #0284c7; }
    .empty { color: #64748b; font-style: italic; }
    .badge { display: inline-block; font-size: 0.75em; font-weight: 600; letter-spacing: 0.03em; }
  `;

  function renderHtmlReport(tool, findings, summary) {
    const findingsHtml = findings.length ? findings.map((f) => `
      <div class="finding ${f.severity || 'info'}">
        <span class="badge">${(f.severity || 'info').toUpperCase()}</span>
        <strong>${escapeHtml(f.title)}</strong>
        <p>${escapeHtml(f.description)}</p>
      </div>`).join('') : '<p class="empty">No findings recorded.</p>';

    const recs = tool.name === 'iacauditor' && findings.length
      ? ['Restrict public ingress rules (0.0.0.0/0) to the specific CIDR ranges that need access.', 'Move hardcoded secrets into environment variables or a secrets manager.']
      : [];
    const recsHtml = recs.length ? `<ul>${recs.map((r) => `<li>${escapeHtml(r)}</li>`).join('')}</ul>` : '<p class="empty">No recommendations recorded.</p>';

    return `<!DOCTYPE html><html><head><meta charset="utf-8"><style>${HTML_REPORT_STYLE}</style></head><body>
      <div class="header"><h1>${niceName(tool.name)} Security Report</h1>
      <div class="meta">Module: ${consoleState.module.toUpperCase()} &middot; Generated: 2026-10-31T12:00:00</div></div>
      <div class="section"><h2>Summary</h2><p>${escapeHtml(summary)}</p></div>
      <div class="section"><h2>Findings (${findings.length})</h2>${findingsHtml}</div>
      <div class="section"><h2>Recommendations</h2>${recsHtml}</div>
      </body></html>`;
  }

  function renderMarkdownReport(tool, findings, summary) {
    const lines = [`# ${niceName(tool.name)} Security Report`, '', `**Module:** ${consoleState.module.toUpperCase()}`, '**Generated:** 2026-10-31T12:00:00', '', '## Summary', '', summary, '', `## Findings (${findings.length})`];
    if (findings.length) {
      findings.forEach((f) => { lines.push(`### ${f.title} — ${(f.severity || 'info').toUpperCase()}`, '', f.description, ''); });
    } else {
      lines.push('_No findings recorded._', '');
    }
    lines.push('## Recommendations');
    lines.push(findings.length ? '- Review each finding and remediate as appropriate.' : '_No recommendations recorded._');
    return lines.join('\n');
  }

  function renderSampleReport() {
    const tool = getTool(consoleState.module, consoleState.tool);
    document.getElementById('report-tool-label').textContent = `${niceName(tool.name)} (${consoleState.module.toUpperCase()})`;
    const findings = reportFindingsFor(tool, consoleState.flags);
    const summary = reportSummaryFor(tool, consoleState.flags);

    const htmlFrame = document.getElementById('report-frame-html');
    const mdPre = document.getElementById('report-frame-md');
    if (reportFormat === 'html') {
      htmlFrame.hidden = false; mdPre.hidden = true;
      htmlFrame.srcdoc = renderHtmlReport(tool, findings, summary);
    } else {
      htmlFrame.hidden = true; mdPre.hidden = false;
      mdPre.textContent = renderMarkdownReport(tool, findings, summary);
    }
  }

  function syncReportsWithConsole() {
    const tool = getTool(consoleState.module, consoleState.tool);
    if (tool && tool.status === 'implemented') renderSampleReport();
  }

  function initReports() {
    document.querySelectorAll('.format-btn').forEach((btn) => {
      btn.addEventListener('click', () => {
        document.querySelectorAll('.format-btn').forEach((b) => b.classList.remove('active'));
        btn.classList.add('active');
        reportFormat = btn.getAttribute('data-format');
        renderSampleReport();
      });
    });
    renderSampleReport();
  }

  /* ----------------------------------------------- authorization checker */

  function initAuthChecker() {
    const btn = document.getElementById('auth-check-btn');
    const input = document.getElementById('auth-target');
    const override = document.getElementById('auth-override');
    const result = document.getElementById('auth-result');

    function run() {
      const target = input.value.trim();
      result.className = 'auth-result';
      if (!target) { result.textContent = ''; return; }
      const host = extractHost(target);
      if (!host) {
        result.classList.add('auth-blocked');
        result.textContent = `Could not determine a host to authorize for target: '${target}'`;
        return;
      }
      const priv = isPrivateHost(host);
      if (priv === true) {
        result.classList.add('auth-allowed');
        result.textContent = `✓ ALLOWED — '${host}' is within loopback/RFC1918 ranges. No --i-have-authorization needed.`;
        return;
      }
      if (priv === 'unknown') {
        result.classList.add('auth-unknown');
        result.textContent = `? CANNOT VERIFY client-side — '${host}' is a hostname, not a literal IP. The real CLI resolves it via DNS (socket.gethostbyname) before deciding; this page doesn't perform DNS lookups.`;
        return;
      }
      if (override.checked) {
        result.classList.add('auth-warn');
        result.textContent = `⚠ PROCEEDING (with warning) — '${target}' is outside private/loopback ranges, but --i-have-authorization was set. Only test systems you are explicitly authorized to assess.`;
      } else {
        result.classList.add('auth-blocked');
        result.textContent = `✗ BLOCKED by default — '${target}' is outside private/loopback ranges. Active scans and attack simulations must be restricted to targets you are explicitly authorized to test. Re-run with --i-have-authorization only if you own this target or hold written permission to test it.`;
      }
    }

    btn.addEventListener('click', run);
    input.addEventListener('keydown', (e) => { if (e.key === 'Enter') run(); });
    override.addEventListener('change', run);
  }

  /* -------------------------------------------------- limitations table */

  function initStatusTable() {
    const table = document.getElementById('status-table');
    const rows = [['Domain', 'Implemented', 'Catalog-only (requires vendor account)']];
    MODULES.forEach((m) => {
      const tools = TOOLS[m.key] || [];
      const implemented = tools.filter((t) => t.status === 'implemented').map((t) => niceName(t.name)).join(', ');
      const catalog = tools.filter((t) => t.status === 'catalog').map((t) => niceName(t.name)).join(', ');
      rows.push([m.label, implemented || '—', catalog || '—']);
    });
    table.innerHTML = rows.map((r, i) => `<tr>${r.map((c) => `<${i === 0 ? 'th' : 'td'}>${escapeHtml(c)}</${i === 0 ? 'th' : 'td'}>`).join('')}</tr>`).join('');
  }

  /* --------------------------------------------------------------- init */

  document.addEventListener('DOMContentLoaded', () => {
    initNav();
    initReveal();
    initHeroTyper();
    renderDomainTabs();
    renderToolGrid();
    renderPresets();
    initConsole();
    initReports();
    initAuthChecker();
    initStatusTable();
  });
})();
