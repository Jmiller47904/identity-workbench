'use strict';

(() => {
  const $ = id => document.getElementById(id);
  const DAY = 86400000;
  const MAX_INPUT = 2000000;
  const MAX_IDENTITIES = 5000;
  const providers = {
    azure: { label: 'Azure / Entra ID' },
    aws: { label: 'Amazon Web Services' },
    gcp: { label: 'Google Cloud' },
    okta: { label: 'Okta' }
  };
  const blockedKeys = new Set([
    'secret', 'secretvalue', 'clientsecret', 'privatekey', 'password',
    'accesstoken', 'refreshtoken', 'idtoken', 'sessiontoken', 'bearertoken',
    'token', 'tokenvalue', 'apikey', 'credential', 'credentialvalue', 'key', 'authorization'
  ]);
  let snapshot = null;
  let identities = [];

  function el(tag, className, value) {
    const item = document.createElement(tag);
    if (className) item.className = className;
    if (value !== undefined && value !== null) item.textContent = String(value);
    return item;
  }

  function setText(id, value) {
    const target = $(id);
    if (target) target.textContent = value == null ? '' : String(value);
  }

  function normalizeKey(key) {
    return String(key).toLowerCase().replace(/[-_ ]/g, '');
  }

  function rejectSecretFields(value) {
    const pending = [{ value, depth: 0 }];
    while (pending.length) {
      const current = pending.pop();
      if (current.depth > 40) throw new Error('Snapshot nesting is too deep to inspect safely.');
      if (!current.value || typeof current.value !== 'object') continue;
      const entries = Array.isArray(current.value)
        ? current.value.map((item, index) => [String(index), item])
        : Object.entries(current.value);
      for (const [key, child] of entries) {
        const normalized = normalizeKey(key);
        const sensitive = blockedKeys.has(normalized) || normalized.includes('secret') || normalized.includes('privatekey') || normalized.endsWith('password');
        if (!Array.isArray(current.value) && sensitive) {
          throw new Error('Secret-bearing fields are not accepted. Remove keys, tokens, passwords, and credential values; include metadata only.');
        }
        if (child && typeof child === 'object') pending.push({ value: child, depth: current.depth + 1 });
      }
    }
  }

  function text(value, limit = 200) {
    if (typeof value !== 'string' && typeof value !== 'number') return '';
    return String(value).trim().slice(0, limit);
  }

  function timestamp(value) {
    if (typeof value !== 'string' && typeof value !== 'number') return '';
    const parsed = Date.parse(value);
    return Number.isFinite(parsed) ? new Date(parsed).toISOString() : '';
  }

  function normalizeOwner(value) {
    if (typeof value === 'string') return { name: text(value), email: '', team: '', evidence: '' };
    if (!value || typeof value !== 'object' || Array.isArray(value)) return { name: '', email: '', team: '', evidence: '' };
    return {
      name: text(value.name || value.displayName),
      email: text(value.email || value.userPrincipalName),
      team: text(value.team || value.teamName),
      evidence: text(value.evidence || value.source, 120)
    };
  }

  function normalizePermissions(value) {
    if (!Array.isArray(value)) return [];
    return value.slice(0, 100).map(item => {
      if (typeof item === 'string') return text(item, 240);
      if (item && typeof item === 'object') {
        const name = text(item.name || item.permission || item.role, 180);
        const scope = text(item.scope, 180);
        return name ? (scope ? name + ' — ' + scope : name) : '';
      }
      return '';
    }).filter(Boolean);
  }

  function normalizeInventory(raw) {
    if (!raw || typeof raw !== 'object' || Array.isArray(raw)) throw new Error('The snapshot must be a JSON object.');
    rejectSecretFields(raw);
    if (raw.schemaVersion !== 1) throw new Error('Unsupported snapshot schema. Set schemaVersion to 1; see the format guide.');
    if (!Array.isArray(raw.identities)) throw new Error('The snapshot must include an identities array.');
    if (raw.identities.length > MAX_IDENTITIES) throw new Error('This local preview is limited to 5,000 identities per snapshot.');
    if (Array.isArray(raw.sources) && raw.sources.length > 1000) throw new Error('This local preview is limited to 1,000 source scopes per snapshot.');

    const sources = Array.isArray(raw.sources) ? raw.sources.map(source => {
      if (!source || typeof source !== 'object' || !providers[source.provider]) return null;
      const coverage = ['complete', 'partial', 'none'].includes(source.activityCoverage) ? source.activityCoverage : 'unknown';
      return {
        provider: source.provider,
        scopeId: text(source.scopeId, 200),
        scopeLabel: text(source.scopeLabel || source.label || source.scopeId, 160),
        activityCoverage: coverage,
        collectedAt: timestamp(source.collectedAt)
      };
    }).filter(Boolean) : [];
    const sourceIndex = new Map(sources.map(source => [source.provider + '|' + source.scopeId, source]));

    const seen = new Set();
    const normalized = raw.identities.map((item, index) => {
      if (!item || typeof item !== 'object' || Array.isArray(item)) throw new Error('Identity ' + (index + 1) + ' must be an object.');
      for (const [field, limit] of Object.entries({ permissions: 100, credentials: 50, activity: 500, trusts: 100 })) {
        if (Array.isArray(item[field]) && item[field].length > limit) throw new Error('Identity ' + (index + 1) + ' exceeds the local ' + field + ' limit of ' + limit + '.');
      }
      if (!providers[item.provider]) throw new Error('Identity ' + (index + 1) + ' has an unsupported provider. Use azure, aws, gcp, or okta.');
      const id = text(item.id, 240);
      const displayName = text(item.displayName || item.name, 240);
      if (!id || !displayName) throw new Error('Identity ' + (index + 1) + ' needs both an id and displayName.');
      const scopeId = text(item.scopeId, 200);
      const unique = item.provider + '|' + scopeId + '|' + id;
      if (seen.has(unique)) throw new Error('Duplicate identity id in the same provider scope: ' + id + '.');
      seen.add(unique);

      const source = sourceIndex.get(item.provider + '|' + scopeId) || sourceIndex.get(item.provider + '|') || null;
      const requestedCoverage = item.activityCoverage;
      const activityCoverage = ['complete', 'partial', 'none'].includes(requestedCoverage)
        ? requestedCoverage
        : (source ? source.activityCoverage : 'unknown');

      const credentials = Array.isArray(item.credentials) ? item.credentials.slice(0, 50).map(credential => {
        if (!credential || typeof credential !== 'object' || Array.isArray(credential)) return null;
        return {
          id: text(credential.id || credential.keyId || credential.credentialId, 120),
          type: text(credential.type || credential.kind, 100) || 'credential',
          active: credential.active !== false,
          managed: credential.managed === true,
          createdAt: timestamp(credential.createdAt || credential.startDateTime),
          expiresAt: timestamp(credential.expiresAt || credential.endDateTime),
          lastUsedAt: timestamp(credential.lastUsedAt || credential.lastUsed)
        };
      }).filter(Boolean) : [];

      const activity = Array.isArray(item.activity) ? item.activity.slice(0, 500).map(event => {
        if (!event || typeof event !== 'object' || Array.isArray(event)) return null;
        return {
          at: timestamp(event.at || event.createdAt || event.timestamp),
          action: text(event.action || event.operation, 180),
          target: text(event.target || event.resource, 180),
          source: text(event.source || event.sourceIp || event.workload, 160),
          outcome: text(event.outcome || event.status, 80)
        };
      }).filter(event => event && event.at) : [];

      const trusts = Array.isArray(item.trusts) ? item.trusts.slice(0, 100).map(trust => {
        if (typeof trust === 'string') return { principal: text(trust, 240), external: false };
        if (!trust || typeof trust !== 'object' || Array.isArray(trust)) return null;
        return { principal: text(trust.principal || trust.subject, 240), external: trust.external === true };
      }).filter(Boolean) : [];

      return {
        provider: item.provider,
        id,
        displayName,
        kind: text(item.kind || item.type, 120) || 'non-human identity',
        scopeId,
        scopeLabel: text(item.scopeLabel || (source && source.scopeLabel), 160),
        enabled: item.enabled !== false,
        owner: normalizeOwner(item.owner),
        workload: text(typeof item.workload === 'string' ? item.workload : item.workload && (item.workload.name || item.workload.displayName), 240),
        workloadType: text(item.workloadType || (item.workload && item.workload.type), 100),
        permissions: normalizePermissions(item.permissions),
        credentials,
        activity,
        trusts,
        activityCoverage,
        providerManaged: item.providerManaged === true
      };
    });

    return { sources, identities: normalized, scannedAt: timestamp(raw.scannedAt) };
  }

  function latestActivity(identity) {
    const dates = identity.activity.map(event => Date.parse(event.at));
    for (const credential of identity.credentials) if (credential.lastUsedAt) dates.push(Date.parse(credential.lastUsedAt));
    const valid = dates.filter(Number.isFinite);
    return valid.length ? new Date(Math.max(...valid)).toISOString() : '';
  }

  function riskFor(identity) {
    const findings = [];
    let score = 0;
    const add = (points, level, title, body) => {
      score += points;
      findings.push({ points, level, title, body });
    };

    const hasOwner = Boolean(identity.owner.name || identity.owner.email || identity.owner.team || identity.providerManaged);
    if (!hasOwner) add(25, 'high', 'No accountable owner', 'No named person or team is present in the supplied snapshot.');
    if (!identity.workload && !identity.providerManaged) add(8, 'medium', 'No workload is linked', 'The snapshot does not identify the application, job, or runtime using this identity.');

    const riskyPermission = identity.permissions.find(permission =>
      /\b(owner|administrator|admin|super admin|global admin|fullcontrol|administratoraccess)\b|\.all\b|(^|[.:/])\*(?=$|[.:/])/i.test(permission)
    );
    if (riskyPermission) add(35, 'high', 'Broad or privileged access', 'Review the grant: ' + riskyPermission + '. Confirm the scope and the workload requirement.');

    if (identity.trusts.some(trust => trust.external || trust.principal === '*')) {
      add(25, 'high', 'External or unrestricted trust', 'A trust entry is marked external or uses a wildcard principal. Confirm the intended trust boundary.');
    }

    const now = Date.now();
    const activeCredentials = identity.credentials.filter(credential => credential.active);
    let expiredActive = false;
    let expiringSoon = false;
    let noExpiry = false;
    let oldCredential = false;
    for (const credential of activeCredentials) {
      const expiry = credential.expiresAt ? Date.parse(credential.expiresAt) : NaN;
      const created = credential.createdAt ? Date.parse(credential.createdAt) : NaN;
      if (Number.isFinite(expiry) && expiry < now) expiredActive = true;
      else if (Number.isFinite(expiry) && expiry - now <= 30 * DAY) expiringSoon = true;
      else if (!Number.isFinite(expiry) && !credential.managed) noExpiry = true;
      if (Number.isFinite(created) && now - created > 365 * DAY && !credential.managed) oldCredential = true;
    }
    if (expiredActive) add(30, 'high', 'Active credential is past its expiry', 'One or more credentials are marked active even though their expiry date has passed.');
    if (expiringSoon) add(12, 'medium', 'Credential expires within 30 days', 'Plan rotation or confirm that the credential is still required.');
    if (noExpiry) add(12, 'medium', 'Active credential has no expiry', 'Review whether this credential can be replaced with a managed identity or short-lived federation.');
    if (oldCredential) add(10, 'medium', 'Credential is older than one year', 'Review its continued use and rotation policy.');
    if (activeCredentials.length >= 3) add(8, 'medium', 'Several active credentials', 'The snapshot shows three or more active credentials. Confirm that each is needed and assigned to a known workload.');

    const last = latestActivity(identity);
    if (last) {
      const age = (now - Date.parse(last)) / DAY;
      if (age > 90) add(15, 'medium', 'No recent activity observed', 'The latest activity in this snapshot is ' + Math.floor(age) + ' days old. Check telemetry coverage before treating the identity as unused.');
    } else if (identity.activityCoverage === 'complete') {
      add(15, 'medium', 'No activity in the covered window', 'The source is marked complete, but the snapshot contains no activity for this identity in its covered window.');
    } else {
      findings.push({ points: 0, level: 'info', title: 'Activity coverage is incomplete', body: 'No activity is included and the source is not marked complete. The scanner cannot determine whether this identity is unused.' });
    }

    score = Math.min(100, score);
    const level = score >= 75 ? 'critical' : score >= 50 ? 'high' : score >= 25 ? 'medium' : score > 0 ? 'low' : 'none';
    return { score, level, findings, lastActivity: last };
  }

  function syntheticSnapshot() {
    const ago = days => new Date(Date.now() - days * DAY).toISOString();
    const ahead = days => new Date(Date.now() + days * DAY).toISOString();
    return {
      schemaVersion: 1,
      scannedAt: new Date().toISOString(),
      sources: [
        { provider: 'azure', scopeId: 'demo-entra', scopeLabel: 'Synthetic Entra tenant', activityCoverage: 'partial', collectedAt: new Date().toISOString() },
        { provider: 'aws', scopeId: 'demo-aws', scopeLabel: 'Synthetic AWS organization', activityCoverage: 'complete', collectedAt: new Date().toISOString() },
        { provider: 'gcp', scopeId: 'demo-gcp', scopeLabel: 'Synthetic Google Cloud organization', activityCoverage: 'partial', collectedAt: new Date().toISOString() },
        { provider: 'okta', scopeId: 'demo-okta', scopeLabel: 'Synthetic Okta org', activityCoverage: 'complete', collectedAt: new Date().toISOString() }
      ],
      identities: [
        {
          provider: 'azure', id: 'spn-demo-001', displayName: 'claims-sync-prod', kind: 'service principal',
          scopeId: 'demo-entra', enabled: true,
          owner: { team: 'Identity Platform', evidence: 'directory owner' },
          workload: 'Claims reconciliation function', workloadType: 'Azure Function',
          permissions: ['User.Read.All'],
          credentials: [{ id: 'cert-demo-a1', type: 'certificate', active: true, managed: false, createdAt: ago(330), expiresAt: ahead(18), lastUsedAt: ago(12) }],
          activity: [{ at: ago(12), action: 'Token issued', target: 'Microsoft Graph', source: 'claims-sync-prod', outcome: 'success' }]
        },
        {
          provider: 'azure', id: 'mi-demo-002', displayName: 'invoice-worker-prod', kind: 'managed identity',
          scopeId: 'demo-entra', enabled: true,
          owner: { team: 'Finance Applications', evidence: 'linked workload tag' },
          workload: 'invoice-worker', workloadType: 'Azure Container App',
          permissions: ['Storage Blob Data Contributor'],
          credentials: [{ id: 'platform-managed', type: 'managed identity', active: true, managed: true }],
          activity: [{ at: ago(2), action: 'Storage read', target: 'invoice-archive', source: 'centralus', outcome: 'success' }]
        },
        {
          provider: 'aws', id: 'role-demo-101', displayName: 'prod-billing-lambda', kind: 'IAM role',
          scopeId: 'demo-aws', enabled: true,
          owner: { team: 'Billing Engineering', evidence: 'resource tag' },
          workload: 'billing-export', workloadType: 'Lambda function',
          permissions: ['s3:GetObject', 'kms:Decrypt'],
          trusts: [{ principal: 'lambda.amazonaws.com', external: false }],
          activity: [{ at: ago(4), action: 'GetObject', target: 'billing-exports', source: 'us-east-1', outcome: 'success' }]
        },
        {
          provider: 'aws', id: 'role-demo-102', displayName: 'legacy-admin-export', kind: 'IAM role',
          scopeId: 'demo-aws', enabled: true,
          workload: '',
          permissions: ['AdministratorAccess'],
          trusts: [{ principal: 'arn:aws:iam::999999999999:role/partner-ops', external: true }],
          activity: [{ at: ago(166), action: 'AssumeRole', target: 'legacy export account', source: 'external account', outcome: 'success' }]
        },
        {
          provider: 'gcp', id: 'sa-demo-201', displayName: 'nightly-reporter', kind: 'service account',
          scopeId: 'demo-gcp', enabled: true,
          owner: { team: 'Data Platform', evidence: 'project label' },
          workload: 'report-generator', workloadType: 'Cloud Run job',
          permissions: ['roles/viewer'],
          credentials: [{ id: 'key-demo-22', type: 'user-managed key', active: true, managed: false, createdAt: ago(820), lastUsedAt: ago(127) }],
          activity: [{ at: ago(127), action: 'GenerateAccessToken', target: 'reporting project', source: 'nightly job', outcome: 'success' }]
        },
        {
          provider: 'okta', id: 'app-demo-301', displayName: 'Okta Audit Exporter', kind: 'OAuth service app',
          scopeId: 'demo-okta', enabled: true,
          owner: { team: 'Security Operations', evidence: 'application owner' },
          workload: 'siem-log-relay', workloadType: 'integration',
          permissions: ['okta.logs.read'],
          credentials: [{ id: 'kid-demo-7', type: 'OAuth client key', active: true, managed: false, createdAt: ago(78), lastUsedAt: ago(8) }],
          activity: [{ at: ago(8), action: 'Read System Log', target: 'Okta org', source: 'siem-log-relay', outcome: 'success' }]
        },
        {
          provider: 'okta', id: 'user-demo-302', displayName: 'svc-hr-import', kind: 'service user',
          scopeId: 'demo-okta', enabled: true,
          permissions: ['okta.users.manage'],
          credentials: [{ id: 'token-demo-55', type: 'API token', active: true, managed: false, createdAt: ago(600), lastUsedAt: ago(204) }],
          activity: [],
          activityCoverage: 'complete'
        }
      ]
    };
  }

  function metric(label, value, hint) {
    const card = el('div', 'nhi-metric');
    card.append(el('span', 'nhi-metric-label', label), el('strong', 'nhi-metric-value', value), el('small', 'nhi-metric-hint', hint));
    return card;
  }

  function renderProviderCards(sourceRecords, rows) {
    const target = $('nhi-provider-cards');
    target.replaceChildren();
    for (const [key, provider] of Object.entries(providers)) {
      const matches = rows.filter(identity => identity.provider === key);
      const scopes = sourceRecords.filter(source => source.provider === key);
      const coverages = [...new Set(scopes.map(source => source.activityCoverage).filter(item => item !== 'unknown'))];
      const card = el('article', 'nhi-provider-card');
      card.append(el('span', 'nhi-provider-name', provider.label), el('strong', 'nhi-provider-count', matches.length + ' identities'));
      const coverageText = scopes.length
        ? 'Activity coverage: ' + (coverages.length === 1 ? coverages[0] : coverages.length ? 'mixed' : 'not stated')
        : (matches.length ? 'Scope and log coverage not stated' : 'No snapshot supplied');
      card.append(el('small', 'nhi-provider-coverage', coverageText));
      if (scopes.length) {
        const scopeNames = scopes.map(source => source.scopeLabel).filter(Boolean);
        if (scopeNames.length) card.append(el('small', 'nhi-provider-scope', scopeNames.join(' · ')));
      }
      target.append(card);
    }
  }

  function detailsFor(identity, risk) {
    const details = el('details', 'nhi-details');
    details.append(el('summary', '', 'Review evidence'));
    const content = el('div', 'nhi-detail-content');
    const addLine = (label, value) => {
      const row = el('div', 'nhi-detail-row');
      row.append(el('strong', '', label), el('span', '', value || 'Not supplied'));
      content.append(row);
    };
    addLine('Scope', identity.scopeLabel || identity.scopeId);
    addLine('Owner', [identity.owner.name, identity.owner.email, identity.owner.team].filter(Boolean).join(' · '));
    addLine('Identity type', identity.kind);
    addLine('Status', identity.enabled ? 'Enabled' : 'Disabled');
    addLine('Owner evidence', identity.owner.evidence);
    addLine('Workload type', identity.workloadType);
    addLine('Activity coverage', identity.activityCoverage);
    addLine('Permissions', identity.permissions.join(', '));
    addLine('Trust', identity.trusts.map(item => item.principal + (item.external ? ' (external)' : '')).join(', '));

    const credentialList = el('ul', 'nhi-evidence-list');
    for (const credential of identity.credentials) {
      const expiry = credential.expiresAt ? 'expires ' + new Date(credential.expiresAt).toLocaleDateString() : 'no expiry stated';
      const used = credential.lastUsedAt ? 'last used ' + new Date(credential.lastUsedAt).toLocaleDateString() : 'no use date';
      credentialList.append(el('li', '', credential.type + (credential.id ? ' · ' + credential.id : '') + ' · ' + (credential.active ? 'active' : 'inactive') + ' · ' + expiry + ' · ' + used));
    }
    if (!identity.credentials.length) credentialList.append(el('li', '', 'No credential metadata supplied.'));
    content.append(el('strong', 'nhi-detail-heading', 'Credential metadata'), credentialList);

    const events = identity.activity.slice().sort((a, b) => Date.parse(b.at) - Date.parse(a.at)).slice(0, 5);
    const eventList = el('ul', 'nhi-evidence-list');
    for (const event of events) {
      const parts = [new Date(event.at).toLocaleString(), event.action, event.target, event.source, event.outcome].filter(Boolean);
      eventList.append(el('li', '', parts.join(' · ')));
    }
    if (!events.length) eventList.append(el('li', '', 'No activity events included.'));
    content.append(el('strong', 'nhi-detail-heading', 'Recent activity'), eventList);

    const findingList = el('ul', 'nhi-evidence-list');
    const sorted = risk.findings.slice().sort((a, b) => b.points - a.points);
    for (const finding of sorted) findingList.append(el('li', '', finding.title + ': ' + finding.body));
    if (!sorted.length) findingList.append(el('li', '', 'No scanner findings for the supplied fields.'));
    content.append(el('strong', 'nhi-detail-heading', 'Why this risk score'), findingList);
    details.append(content);
    return details;
  }

  function filteredRows() {
    if (!snapshot) return [];
    const provider = $('nhi-filter-provider').value;
    const level = $('nhi-filter-risk').value;
    const query = $('nhi-search').value.trim().toLocaleLowerCase();
    return identities.filter(identity => {
      if (provider && identity.provider !== provider) return false;
      const risk = riskFor(identity);
      if (level && risk.level !== level) return false;
      const haystack = [
        identity.displayName, identity.id, identity.kind, identity.owner.name,
        identity.owner.email, identity.owner.team, identity.workload,
        ...identity.activity.map(event => [event.action, event.target, event.source].filter(Boolean).join(' ')),
        ...identity.permissions
      ].join(' ').toLocaleLowerCase();
      return !query || haystack.includes(query);
    }).sort((a, b) => riskFor(b).score - riskFor(a).score || a.displayName.localeCompare(b.displayName));
  }

  function renderRows() {
    const body = $('nhi-rows');
    body.replaceChildren();
    const matches = filteredRows();
    if (!matches.length) {
      const row = el('tr');
      const cell = el('td', 'nhi-empty-row', snapshot ? 'No identities match these filters.' : 'Load a synthetic sample or analyze a JSON snapshot.');
      cell.colSpan = 7;
      row.append(cell);
      body.append(row);
      setText('nhi-visible-count', '0 identities');
      return;
    }
    for (const identity of matches) {
      const risk = riskFor(identity);
      const row = el('tr', 'nhi-identity-row');
      const identityCell = el('td');
      identityCell.append(el('strong', 'nhi-identity-name', identity.displayName), el('small', 'nhi-identity-id', identity.id));
      const providerCell = el('td');
      providerCell.append(el('span', 'nhi-provider-tag nhi-provider-' + identity.provider, providers[identity.provider].label));
      providerCell.append(el('small', 'nhi-identity-kind', identity.kind));
      const ownerCell = el('td');
      ownerCell.append(el('span', '', identity.owner.name || identity.owner.email || identity.owner.team || (identity.providerManaged ? 'Provider managed' : 'Unassigned')));
      if (identity.owner.name && identity.owner.team) ownerCell.append(el('small', 'nhi-identity-kind', identity.owner.team));
      const workloadCell = el('td', '', identity.workload || 'Not linked');
      const activityCell = el('td');
      activityCell.append(el('span', '', risk.lastActivity ? new Date(risk.lastActivity).toLocaleDateString() : 'No activity included'));
      const lastEvent = identity.activity.slice().sort((a, b) => Date.parse(b.at) - Date.parse(a.at))[0];
      if (lastEvent) activityCell.append(el('small', 'nhi-identity-kind', [lastEvent.action, lastEvent.target].filter(Boolean).join(' · ') || 'Activity event'));
      else if (risk.lastActivity) activityCell.append(el('small', 'nhi-identity-kind', 'Credential usage metadata'));
      activityCell.append(el('small', 'nhi-identity-kind', identity.activityCoverage + ' coverage'));
      const riskCell = el('td');
      const badge = el('span', 'nhi-risk nhi-risk-' + risk.level, risk.level.toUpperCase() + ' · ' + risk.score);
      riskCell.append(badge);
      const detailCell = el('td');
      detailCell.append(detailsFor(identity, risk));
      row.append(identityCell, providerCell, ownerCell, workloadCell, activityCell, riskCell, detailCell);
      body.append(row);
    }
    setText('nhi-visible-count', matches.length + ' of ' + identities.length + ' identities');
  }

  function renderResults() {
    const results = identities.map(identity => ({ identity, risk: riskFor(identity) }));
    const highCount = results.filter(item => item.risk.level === 'critical' || item.risk.level === 'high').length;
    const ownedCount = identities.filter(identity => identity.owner.name || identity.owner.email || identity.owner.team || identity.providerManaged).length;
    const activityCount = results.filter(item => item.risk.lastActivity).length;
    $('nhi-metrics').replaceChildren(
      metric('Identities', identities.length, 'from this snapshot'),
      metric('High or critical', highCount, 'based on supplied evidence'),
      metric('Owner mapped', ownedCount + ' / ' + identities.length, 'person, team, or provider owner'),
      metric('Activity reported', activityCount + ' / ' + identities.length, 'at least one event or key use')
    );
    renderProviderCards(snapshot.sources, identities);
    $('nhi-results').hidden = false;
    renderRows();
    const sourceTime = snapshot.scannedAt ? new Date(snapshot.scannedAt).toLocaleString() : 'not stated';
    setText('nhi-status', 'Analyzed ' + identities.length + ' identities locally. Snapshot timestamp: ' + sourceTime + '.');
  }

  function analyze() {
    $('nhi-error').textContent = '';
    $('nhi-results').hidden = true;
    try {
      const input = $('nhi-input').value;
      if (!input.trim()) throw new Error('Paste a normalized snapshot or load the synthetic example first.');
      if (input.length > MAX_INPUT) throw new Error('Snapshot exceeds the 2 MB local preview limit.');
      const parsed = JSON.parse(input);
      snapshot = normalizeInventory(parsed);
      identities = snapshot.identities.map(identity => {
        identity.risk = riskFor(identity);
        return identity;
      });
      renderResults();
    } catch (error) {
      snapshot = null;
      identities = [];
      $('nhi-error').textContent = error instanceof Error ? error.message : 'The snapshot could not be analyzed.';
      setText('nhi-status', 'No snapshot analyzed.');
      $('nhi-results').hidden = true;
    }
  }

  function clear() {
    $('nhi-input').value = '';
    $('nhi-file').value = '';
    $('nhi-error').textContent = '';
    $('nhi-search').value = '';
    $('nhi-filter-provider').value = '';
    $('nhi-filter-risk').value = '';
    snapshot = null;
    identities = [];
    $('nhi-results').hidden = true;
    setText('nhi-status', 'Snapshot cleared from page memory.');
    $('nhi-input').focus();
  }

  $('nhi-run').addEventListener('click', analyze);
  $('nhi-sample').addEventListener('click', () => {
    $('nhi-input').value = JSON.stringify(syntheticSnapshot(), null, 2);
    analyze();
  });
  $('nhi-clear').addEventListener('click', clear);
  $('nhi-file').addEventListener('change', async event => {
    const file = event.target.files && event.target.files[0];
    if (!file) return;
    $('nhi-results').hidden = true;
    snapshot = null;
    identities = [];
    if (file.size > MAX_INPUT) {
      $('nhi-error').textContent = 'Snapshot exceeds the 2 MB local preview limit.';
      event.target.value = '';
      return;
    }
    try {
      $('nhi-input').value = await file.text();
      $('nhi-error').textContent = '';
      setText('nhi-status', 'Loaded ' + file.name + ' into page memory. Select Analyze snapshot locally to continue.');
      $('nhi-results').hidden = true;
      snapshot = null;
      identities = [];
    } catch (_) {
      $('nhi-error').textContent = 'The selected file could not be read as UTF-8 text.';
    }
    event.target.value = '';
  });
  $('nhi-input').addEventListener('input', () => {
    if (snapshot) {
      snapshot = null;
      identities = [];
      $('nhi-results').hidden = true;
      setText('nhi-status', 'Snapshot changed. Analyze it again to refresh results.');
    }
  });
  $('nhi-filter-provider').addEventListener('change', renderRows);
  $('nhi-filter-risk').addEventListener('change', renderRows);
  $('nhi-search').addEventListener('input', renderRows);
})();