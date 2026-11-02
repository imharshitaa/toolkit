/*
 * ToolKit interactive simulator — data model.
 *
 * Every field here is transcribed from the actual Python implementation
 * (toolkit/cli.py, toolkit/deploy.py, toolkit/scan.py, toolkit/report.py,
 * toolkit/open_dashboard.py, toolkit/core.py, toolkit/security.py, and each
 * modules/<DOMAIN>/<tool>/*.py) as of the version this page was built
 * against. Nothing here is invented — where the CLI accepts a flag that a
 * given module ignores, or a path that errors, that nuance is recorded in
 * `notes` rather than smoothed over.
 *
 * This file powers a client-side DEMONSTRATION ONLY. No command shown here
 * is executed by this page. Copy a generated command and run it against a
 * real clone of https://github.com/imharshitaa/toolkit.
 */

const MODULES = [
  { key: 'soc', label: 'SOC', full: 'Security Operations Center', desc: 'Centralized log ingestion, alerting, and detection.' },
  { key: 'edr', label: 'EDR', full: 'Endpoint Detection & Response', desc: 'Endpoint agent monitoring and response.' },
  { key: 'netsec', label: 'NetSec', full: 'Network Security', desc: 'Reconnaissance and network exposure mapping.' },
  { key: 'appsec', label: 'AppSec', full: 'Application Security', desc: 'Dynamic web application testing.' },
  { key: 'cloudsec', label: 'CloudSec', full: 'Cloud Security', desc: 'Infrastructure-as-code auditing.' },
  { key: 'vm', label: 'VM', full: 'Vulnerability Management', desc: 'CVE scanning for containers and filesystems.' },
  { key: 'aisec', label: 'AISec', full: 'AI Security', desc: 'LLM risk pattern scanning.' },
];

// Mirrors toolkit/core.py::get_available_tools() exactly (name/type/status/description).
// Extra fields (operations, environments, notes, etc.) are added for implemented tools only,
// sourced from each module's deploy.py / scan.py / simulate.py / report.py / config.py.
const TOOLS = {
  soc: [
    {
      name: 'splunk', type: 'Enterprise', status: 'implemented',
      description: 'SIEM platform for security monitoring',
      needs: 'Docker, or your own AWS/kubeconfig credentials for cloud paths',
      noPriorMessage: "No prior Splunk scan/simulate/deploy result found. Run one first, e.g. 'toolkit scan soc splunk --simulate' or 'toolkit deploy soc splunk'.",
      operations: {
        deploy: { supported: true, note: "Supports docker, local, aws, and kubernetes — all four paths are implemented in modules/SOC/splunk/deploy.py (deploy_docker/deploy_local/deploy_aws/deploy_kubernetes)." },
        scan: { supported: 'simulate-only', note: "There is no modules/SOC/splunk/scan.py — only simulate.py exists. Running `toolkit scan soc splunk` without --simulate fails to load an operation module. Always pass --simulate." },
        report: { supported: true, note: 'Renders the most recent deploy/simulate result.' },
        open: { supported: true, note: "DASHBOARD_URLS['splunk'] = http://localhost:8000" },
      },
      environments: ['docker', 'local', 'aws', 'kubernetes'],
      defaultEnvironment: 'docker',
      dashboardUrl: 'http://localhost:8000',
      simulateOnly: true,
      scenarios: [
        { key: 'all', label: 'all (every scenario)' },
        { key: 'brute_force', label: 'brute_force — T1110 Credential Access (50 events)' },
        { key: 'lateral_movement', label: 'lateral_movement — T1021 Lateral Movement (30 events)' },
        { key: 'data_exfiltration', label: 'data_exfiltration — T1048 Exfiltration (20 events)' },
        { key: 'privilege_escalation', label: 'privilege_escalation — T1078 Privilege Escalation (15 events)' },
        { key: 'persistence', label: 'persistence — T1053 Persistence (10 events)' },
      ],
      targetPlaceholder: 'localhost:8088',
      authEnforced: true,
      sampleFindingsFn: (scenario) => {
        const s = scenario && scenario !== 'all' ? scenario : 'brute_force';
        const map = {
          brute_force: { title: 'MITRE ATT&CK T1110 — Brute Force', severity: 'medium', desc: '50 synthetic brute-force auth events delivered for tactic Credential Access.' },
          lateral_movement: { title: 'MITRE ATT&CK T1021 — Remote Services', severity: 'high', desc: '30 synthetic lateral-movement events delivered for tactic Lateral Movement.' },
          data_exfiltration: { title: 'MITRE ATT&CK T1048 — Exfiltration Over Alternative Protocol', severity: 'high', desc: '20 synthetic exfiltration events delivered for tactic Exfiltration.' },
          privilege_escalation: { title: 'MITRE ATT&CK T1078 — Valid Accounts', severity: 'high', desc: '15 synthetic privilege-escalation events delivered for tactic Privilege Escalation.' },
          persistence: { title: 'MITRE ATT&CK T1053 — Scheduled Task/Job', severity: 'high', desc: '10 synthetic persistence events delivered for tactic Persistence.' },
        };
        return [map[s]];
      },
      summaryFn: (target, scenario) => `Ran ${scenario === 'all' ? 5 : 1} MITRE ATT&CK-aligned scenario(s) against ${target}, generating synthetic events.`,
    },
    {
      name: 'wazuh', type: 'Open Source', status: 'implemented',
      description: 'Open source security monitoring',
      needs: 'Docker',
      noPriorMessage: "No prior Wazuh deploy/scan result found. Run 'toolkit deploy soc wazuh' first.",
      operations: {
        deploy: { supported: true, note: "Always runs the labs/docker/ Compose stack (manager + indexer + dashboard) — the --environment flag is accepted by the CLI but ignored by this module; Wazuh here is docker-only." },
        scan: { supported: true, note: '"Scan" is a health check of the running containers, not a new scan. --target is required by the shared CLI option but is ignored by this module — pass any placeholder value.' },
        report: { supported: true, note: 'Renders the most recent health-check result.' },
        open: { supported: true, note: "DASHBOARD_URLS['wazuh'] = http://localhost:5601/app/wazuh" },
      },
      environments: ['docker'],
      defaultEnvironment: 'docker',
      dashboardUrl: 'http://localhost:5601/app/wazuh',
      targetPlaceholder: 'localhost (ignored by this module)',
      targetIgnored: true,
      authEnforced: false,
      sampleFindings: [
        { title: 'wazuh (wazuh-manager)', severity: 'info', desc: 'Status: running.' },
        { title: 'wazuh-indexer (wazuh-indexer)', severity: 'info', desc: 'Status: running.' },
        { title: 'wazuh-dashboard (wazuh-dashboard)', severity: 'high', desc: 'Status: exited. Container stopped unexpectedly.' },
      ],
      summaryFn: () => '2/3 Wazuh containers running at scan time.',
    },
    { name: 'sentinel', type: 'Cloud', status: 'catalog', description: 'Microsoft cloud-native SIEM' },
    { name: 'qradar', type: 'Enterprise', status: 'catalog', description: 'IBM security analytics platform' },
    { name: 'elastic', type: 'Open Source', status: 'catalog', description: 'Elasticsearch-based SIEM' },
  ],
  edr: [
    {
      name: 'wazuh', type: 'Open Source', status: 'implemented',
      description: 'Open source EDR solution (shares the SOC/wazuh backend)',
      needs: 'Docker',
      noPriorMessage: "No prior Wazuh deploy/scan result found. Run 'toolkit deploy soc wazuh' first.",
      delegatesTo: 'soc/wazuh',
      operations: {
        deploy: { supported: true, note: 'modules/EDR/wazuh re-exports modules/SOC/wazuh — identical behavior, same Compose stack.' },
        scan: { supported: true, note: 'Same health check as SOC → Wazuh. --target is required by the CLI but ignored.' },
        report: { supported: true, note: 'Renders the most recent health-check result.' },
        open: { supported: true, note: "DASHBOARD_URLS['wazuh'] = http://localhost:5601/app/wazuh" },
      },
      environments: ['docker'],
      defaultEnvironment: 'docker',
      dashboardUrl: 'http://localhost:5601/app/wazuh',
      targetPlaceholder: 'localhost (ignored by this module)',
      targetIgnored: true,
      authEnforced: false,
      sampleFindings: [
        { title: 'wazuh (wazuh-manager)', severity: 'info', desc: 'Status: running.' },
        { title: 'wazuh-indexer (wazuh-indexer)', severity: 'info', desc: 'Status: running.' },
        { title: 'wazuh-dashboard (wazuh-dashboard)', severity: 'info', desc: 'Status: running.' },
      ],
      summaryFn: () => '3/3 Wazuh containers running at scan time.',
    },
    { name: 'crowdstrike', type: 'Enterprise', status: 'catalog', description: 'Cloud-native endpoint protection' },
    { name: 'sentinelone', type: 'Enterprise', status: 'catalog', description: 'AI-powered endpoint security' },
    { name: 'defender', type: 'Enterprise', status: 'catalog', description: 'Microsoft endpoint protection' },
  ],
  netsec: [
    {
      name: 'nmap', type: 'Open Source', status: 'implemented',
      description: 'Network discovery and port scanning',
      needs: 'nmap installed locally',
      noPriorMessage: "No prior nmap scan found. Run 'toolkit scan netsec nmap --target <host>' first.",
      operations: {
        deploy: { supported: false, note: 'No deploy.py — nmap wraps a local binary, there is nothing to deploy.' },
        scan: { supported: true, note: 'Wraps the nmap binary, parses real XML output.' },
        report: { supported: true, note: 'Renders the most recent scan result.' },
        open: { supported: false, note: "nmap has no entry in DASHBOARD_URLS — `toolkit open netsec nmap` prints \"No default URL configured for nmap\" unless --host/--port are given." },
      },
      scanTypeMap: {
        quick: '-T4 -F', full: '-T4 -p- -sV', stealth: '-sS -T2',
        compliance: '-T4 -p- -sV (falls back to the "full" flag set)',
        custom: '-T4 -p- -sV (falls back to the "full" flag set)',
      },
      targetPlaceholder: '192.168.1.0/24',
      portsRelevant: true,
      authEnforced: true,
      sampleFindingsFn: () => [
        { title: 'Open port 22/tcp (ssh)', severity: 'medium', desc: 'Port 22/tcp open on 192.168.1.14 running ssh (OpenSSH 8.9).' },
        { title: 'Open port 80/tcp (http)', severity: 'medium', desc: 'Port 80/tcp open on 192.168.1.14 running http (nginx 1.24.0).' },
        { title: 'Open port 445/tcp (microsoft-ds)', severity: 'medium', desc: 'Port 445/tcp open on 192.168.1.22 running microsoft-ds.' },
      ],
      summaryFn: (target, scanType) => `Scanned ${target} (${scanType} profile): 2 host(s) up, 3 open port(s).`,
    },
    { name: 'paloalto', type: 'Enterprise', status: 'catalog', description: 'Next-gen firewall platform' },
    { name: 'fortinet', type: 'Enterprise', status: 'catalog', description: 'FortiGate security appliance' },
    { name: 'cisco', type: 'Enterprise', status: 'catalog', description: 'Cisco security solutions' },
    { name: 'opnsense', type: 'Open Source', status: 'catalog', description: 'Open source firewall' },
  ],
  appsec: [
    {
      name: 'zap', type: 'Open Source', status: 'implemented',
      description: 'OWASP ZAP web application scanning',
      needs: 'Docker',
      noPriorMessage: "No prior ZAP scan found. Run 'toolkit scan appsec zap --target <url>' first.",
      operations: {
        deploy: { supported: true, note: "Only environment=docker is implemented — modules/APPSEC/zap/deploy.py explicitly errors on any other value, even though 'local' appears in its DEPLOYMENT_CONFIG." },
        scan: { supported: true, note: "Drives a running ZAP daemon's REST API: spiders the target, and for any --scan-type other than 'quick' also runs an active scan." },
        report: { supported: true, note: 'Renders the most recent scan result.' },
        open: { supported: true, note: "DASHBOARD_URLS['zap'] = http://localhost:8080" },
      },
      environments: ['docker', 'local'],
      defaultEnvironment: 'docker',
      environmentNote: "'local' is accepted by the CLI but modules/APPSEC/zap/deploy.py rejects anything except 'docker'.",
      dashboardUrl: 'http://localhost:8080',
      targetPlaceholder: 'http://localhost:8081',
      authEnforced: true,
      timeoutIgnored: true,
      sampleFindingsFn: (scanType) => {
        const base = [
          { title: 'Cross Site Scripting (Reflected)', severity: 'high', desc: 'Reflected XSS detected in a query parameter.' },
          { title: 'X-Content-Type-Options Header Missing', severity: 'low', desc: 'Response did not include the X-Content-Type-Options header.' },
        ];
        if (scanType !== 'quick') {
          base.push({ title: 'SQL Injection', severity: 'high', desc: 'Active scan found a time-based blind SQL injection point.' });
        }
        return base;
      },
      summaryFn: (target, scanType) => `${scanType !== 'quick' ? 'Spider + active scan' : 'Spider (passive) scan'} of ${target} found ${scanType !== 'quick' ? 3 : 2} alert(s).`,
    },
    { name: 'burpsuite', type: 'Enterprise', status: 'catalog', description: 'Web application security testing' },
    { name: 'nuclei', type: 'Open Source', status: 'catalog', description: 'Vulnerability scanner' },
    { name: 'postman', type: 'Tool', status: 'catalog', description: 'API security testing' },
  ],
  cloudsec: [
    {
      name: 'iacauditor', type: 'Open Source', status: 'implemented',
      description: 'Static Terraform/Docker Compose misconfiguration scanner',
      needs: 'Nothing — zero dependencies, zero network access',
      noPriorMessage: "No prior IaC Auditor scan found. Run 'toolkit scan cloudsec iacauditor --target <dir>' first.",
      operations: {
        deploy: { supported: false, note: 'No deploy.py — pure static analysis, nothing to deploy.' },
        scan: { supported: true, note: 'Pure-Python regex/YAML scan over .tf and docker-compose.y*ml files. --scan-type is accepted by the CLI but ignored by this module.' },
        report: { supported: true, note: 'Renders the most recent scan result.' },
        open: { supported: false, note: 'No entry in DASHBOARD_URLS — there is no dashboard for a static scanner.' },
      },
      scanTypeIgnored: true,
      targetPlaceholder: 'labs/',
      authEnforced: false,
      sampleFindingsFn: () => [
        { title: 'Public ingress on port 22 (SSH access)', severity: 'critical', desc: "labs/terraform/aws_lab.tf: security group rule allows 0.0.0.0/0 on port 22, which exposes SSH." },
        { title: "Hardcoded secret value for 'admin_password'", severity: 'high', desc: 'labs/docker/docker-compose.yml: \'admin_password\' is assigned a literal string instead of a variable reference.' },
      ],
      zeroFindingsSummary: 'Scanned 2 file(s) under labs/: 0 finding(s).',
      summaryFn: (target) => `Scanned 2 file(s) under ${target}: 2 finding(s).`,
    },
    { name: 'guardduty', type: 'Cloud', status: 'catalog', description: 'AWS threat detection' },
    { name: 'securityhub', type: 'Cloud', status: 'catalog', description: 'AWS security posture management' },
    { name: 'prismacloud', type: 'Enterprise', status: 'catalog', description: 'Palo Alto cloud security' },
    { name: 'mandiant', type: 'Enterprise', status: 'catalog', description: 'Google Cloud security' },
  ],
  vm: [
    {
      name: 'trivy', type: 'Open Source', status: 'implemented',
      description: 'Filesystem and container image CVE scanning',
      needs: 'trivy installed locally',
      noPriorMessage: "No prior Trivy scan found. Run 'toolkit scan vm trivy --target <path-or-image>' first.",
      operations: {
        deploy: { supported: false, note: 'No deploy.py — trivy wraps a local binary, there is nothing to deploy.' },
        scan: { supported: true, note: "Wraps the trivy binary in 'fs' or 'image' mode (auto-detected from whether --target exists on disk — there is no --target-type flag), parses real JSON CVE output." },
        report: { supported: true, note: 'Renders the most recent scan result.' },
        open: { supported: false, note: 'No entry in DASHBOARD_URLS — there is no dashboard for a CLI scanner.' },
      },
      scanTypeMap: {
        quick: 'CRITICAL,HIGH', full: 'CRITICAL,HIGH,MEDIUM,LOW,UNKNOWN', stealth: 'CRITICAL,HIGH',
        compliance: 'CRITICAL,HIGH,MEDIUM,LOW,UNKNOWN', custom: 'CRITICAL,HIGH,MEDIUM,LOW,UNKNOWN',
      },
      targetPlaceholder: '.',
      authEnforced: 'image-only',
      sampleFindingsFn: () => [
        { title: 'CVE-2023-44487 in golang.org/x/net', severity: 'high', desc: 'golang.org/x/net 0.17.0 in . is affected by CVE-2023-44487. Fixed in 0.17.0.' },
        { title: 'CVE-2024-3094 in liblzma5', severity: 'critical', desc: 'liblzma5 5.6.0 in . is affected by CVE-2024-3094. No fix currently available.' },
      ],
      summaryFn: (target, scanType, severity) => `Scanned ${target} (fs): 2 vulnerabilit(y/ies) at or above ${severity}.`,
    },
    { name: 'tenable', type: 'Enterprise', status: 'catalog', description: 'Nessus vulnerability scanner' },
    { name: 'qualys', type: 'Enterprise', status: 'catalog', description: 'Cloud-based VM platform' },
    { name: 'rapid7', type: 'Enterprise', status: 'catalog', description: 'Nexpose vulnerability management' },
    { name: 'openvas', type: 'Open Source', status: 'catalog', description: 'Open source scanner' },
  ],
  aisec: [
    {
      name: 'llmriskscanner', type: 'Open Source', status: 'implemented',
      description: 'Heuristic OWASP LLM Top 10 pattern scanner for transcripts/logs',
      needs: 'Nothing — zero dependencies, zero network access',
      noPriorMessage: "No prior LLM Risk Scanner result found. Run 'toolkit scan aisec llmriskscanner --target <file-or-dir>' first.",
      operations: {
        deploy: { supported: false, note: 'No deploy.py — pure static analysis, nothing to deploy.' },
        scan: { supported: true, note: 'Regex pattern match for prompt-injection, insecure-output, and sensitive-data categories across transcript/log files. --scan-type is accepted by the CLI but ignored by this module.' },
        report: { supported: true, note: 'Renders the most recent scan result.' },
        open: { supported: false, note: 'No entry in DASHBOARD_URLS — there is no dashboard for a static scanner.' },
      },
      scanTypeIgnored: true,
      targetPlaceholder: '/path/to/transcript.log',
      authEnforced: false,
      sampleFindingsFn: () => [
        { title: 'Instruction override attempt (transcript.log:42)', severity: 'high', desc: 'transcript.log:42 — "...please ignore all previous instructions and..."' },
        { title: 'Likely AWS access key (transcript.log:108)', severity: 'critical', desc: 'transcript.log:108 — "...key is AKIA************..."' },
      ],
      summaryFn: (target) => `Scanned 1 file(s) under ${target}: 2 pattern match(es). Heuristic pattern matching — review each finding manually before acting on it.`,
    },
    { name: 'darktrace', type: 'Enterprise', status: 'catalog', description: 'AI-powered threat detection' },
    { name: 'vectra', type: 'Enterprise', status: 'catalog', description: 'Network detection and response' },
  ],
};

// toolkit/scan.py --scan-type choices (shared across every tool's scan command).
const SCAN_TYPES = ['quick', 'full', 'stealth', 'compliance', 'custom'];

// toolkit/report.py --severity-filter choices.
const SEVERITY_FILTERS = ['all', 'critical', 'high', 'medium', 'low'];

// toolkit/deploy.py --environment choices (shared CLI option; per-tool support varies, see TOOLS[].environments).
const ALL_ENVIRONMENTS = ['docker', 'local', 'aws', 'kubernetes'];

// toolkit/security.py — private/loopback ranges exempt from the authorization guardrail.
const PRIVATE_RANGES = [
  { label: '127.0.0.0/8 (loopback)', test: (o) => o[0] === 127 },
  { label: '10.0.0.0/8 (RFC1918)', test: (o) => o[0] === 10 },
  { label: '172.16.0.0/12 (RFC1918)', test: (o) => o[0] === 172 && o[1] >= 16 && o[1] <= 31 },
  { label: '192.168.0.0/16 (RFC1918)', test: (o) => o[0] === 192 && o[1] === 168 },
];

// Hand-picked, realistic preset commands — one per implemented tool — mirroring
// the exact invocations shown in the project README's Usage section.
const PRESETS = [
  { module: 'cloudsec', tool: 'iacauditor', op: 'scan', label: 'IaC audit (no deploy, no creds)', flags: { target: 'labs/' } },
  { module: 'aisec', tool: 'llmriskscanner', op: 'scan', label: 'LLM transcript scan', flags: { target: '/path/to/transcript.log' } },
  { module: 'netsec', tool: 'nmap', op: 'scan', label: 'nmap quick sweep', flags: { target: '192.168.1.0/24', scanType: 'quick' } },
  { module: 'vm', tool: 'trivy', op: 'scan', label: 'Trivy filesystem scan', flags: { target: '.', scanType: 'full' } },
  { module: 'appsec', tool: 'zap', op: 'scan', label: 'ZAP scan against a local target', flags: { target: 'http://localhost:8081', scanType: 'quick' } },
  { module: 'soc', tool: 'wazuh', op: 'deploy', label: 'Deploy Wazuh stack', flags: { environment: 'docker' } },
  { module: 'soc', tool: 'splunk', op: 'scan', label: 'Splunk brute-force simulation', flags: { target: 'localhost:8088', simulate: true, scenario: 'brute_force' } },
  { module: 'cloudsec', tool: 'iacauditor', op: 'report', label: 'Markdown report from last scan', flags: { format: 'markdown' } },
];
