/**
 * ASAT — Network Scanner Page
 */
const ScannerPage = {
    async render() {
        const content = document.getElementById('page-content');
        content.innerHTML = `
            <div class="animate-fadeIn">
                <div class="page-header">
                    <div><h1>Network Scanner</h1><p class="page-description">Port scanning, DNS, SSL, HTTP headers, WHOIS, and network diagnostics</p></div>
                </div>

                <div class="tabs">
                    <button class="tab active" data-tab="portscan" onclick="ScannerPage.switchTab('portscan')">🔌 Port Scan</button>
                    <button class="tab" data-tab="dns" onclick="ScannerPage.switchTab('dns')">🌐 DNS Lookup</button>
                    <button class="tab" data-tab="ssl" onclick="ScannerPage.switchTab('ssl')">🔒 SSL Check</button>
                    <button class="tab" data-tab="http" onclick="ScannerPage.switchTab('http')">📡 HTTP Headers</button>
                    <button class="tab" data-tab="whois" onclick="ScannerPage.switchTab('whois')">🔎 WHOIS</button>
                    <button class="tab" data-tab="ping" onclick="ScannerPage.switchTab('ping')">📶 Ping</button>
                    <button class="tab" data-tab="trace" onclick="ScannerPage.switchTab('trace')">🗺️ Traceroute</button>
                </div>

                <!-- Port Scan -->
                <div id="scan-tab-portscan">
                    <div class="card">
                        <div class="card-body">
                            <div class="flex gap-3 items-center flex-wrap">
                                <div class="form-group" style="flex:1;min-width:200px">
                                    <label class="form-label">Target (IP/Hostname)</label>
                                    <input class="form-input" id="ps-target" placeholder="e.g., 192.168.1.1 or example.com">
                                </div>
                                <div class="form-group" style="width:200px">
                                    <label class="form-label">Ports</label>
                                    <input class="form-input" id="ps-ports" value="common" placeholder="1-1024, common, 80,443">
                                </div>
                                <button class="btn btn-primary" onclick="ScannerPage.portScan()" style="margin-top:auto">🚀 Scan</button>
                            </div>
                        </div>
                    </div>
                    <div id="ps-results" style="margin-top:var(--space-4)"></div>
                </div>

                <!-- DNS -->
                <div id="scan-tab-dns" class="hidden">
                    <div class="card">
                        <div class="card-body flex gap-3 items-center flex-wrap">
                            <div class="form-group" style="flex:1;min-width:200px">
                                <label class="form-label">Domain</label>
                                <input class="form-input" id="dns-domain" placeholder="example.com">
                            </div>
                            <button class="btn btn-primary" onclick="ScannerPage.dnsLookup()" style="margin-top:auto">🔍 Lookup</button>
                        </div>
                    </div>
                    <div id="dns-results" style="margin-top:var(--space-4)"></div>
                </div>

                <!-- SSL -->
                <div id="scan-tab-ssl" class="hidden">
                    <div class="card">
                        <div class="card-body flex gap-3 items-center flex-wrap">
                            <div class="form-group" style="flex:1"><label class="form-label">Host</label><input class="form-input" id="ssl-host" placeholder="example.com"></div>
                            <div class="form-group" style="width:100px"><label class="form-label">Port</label><input class="form-input" id="ssl-port" value="443" type="number"></div>
                            <button class="btn btn-primary" onclick="ScannerPage.sslCheck()" style="margin-top:auto">🔒 Check</button>
                        </div>
                    </div>
                    <div id="ssl-results" style="margin-top:var(--space-4)"></div>
                </div>

                <!-- HTTP Headers -->
                <div id="scan-tab-http" class="hidden">
                    <div class="card">
                        <div class="card-body flex gap-3 items-center flex-wrap">
                            <div class="form-group" style="flex:1"><label class="form-label">URL</label><input class="form-input" id="http-url" placeholder="https://example.com"></div>
                            <button class="btn btn-primary" onclick="ScannerPage.httpHeaders()" style="margin-top:auto">📡 Analyze</button>
                        </div>
                    </div>
                    <div id="http-results" style="margin-top:var(--space-4)"></div>
                </div>

                <!-- WHOIS -->
                <div id="scan-tab-whois" class="hidden">
                    <div class="card">
                        <div class="card-body flex gap-3 items-center flex-wrap">
                            <div class="form-group" style="flex:1"><label class="form-label">Domain</label><input class="form-input" id="whois-domain" placeholder="example.com"></div>
                            <button class="btn btn-primary" onclick="ScannerPage.whois()" style="margin-top:auto">🔎 Lookup</button>
                        </div>
                    </div>
                    <div id="whois-results" style="margin-top:var(--space-4)"></div>
                </div>

                <!-- Ping -->
                <div id="scan-tab-ping" class="hidden">
                    <div class="card">
                        <div class="card-body flex gap-3 items-center flex-wrap">
                            <div class="form-group" style="flex:1"><label class="form-label">Target</label><input class="form-input" id="ping-target" placeholder="8.8.8.8 or example.com"></div>
                            <div class="form-group" style="width:100px"><label class="form-label">Count</label><input class="form-input" id="ping-count" value="4" type="number" min="1" max="20"></div>
                            <button class="btn btn-primary" onclick="ScannerPage.ping()" style="margin-top:auto">📶 Ping</button>
                        </div>
                    </div>
                    <div id="ping-results" style="margin-top:var(--space-4)"></div>
                </div>

                <!-- Traceroute -->
                <div id="scan-tab-trace" class="hidden">
                    <div class="card">
                        <div class="card-body flex gap-3 items-center flex-wrap">
                            <div class="form-group" style="flex:1"><label class="form-label">Target</label><input class="form-input" id="trace-target" placeholder="example.com"></div>
                            <button class="btn btn-primary" onclick="ScannerPage.traceroute()" style="margin-top:auto">🗺️ Trace</button>
                        </div>
                    </div>
                    <div id="trace-results" style="margin-top:var(--space-4)"></div>
                </div>
            </div>
        `;
    },

    switchTab(tab) {
        document.querySelectorAll('[id^="scan-tab-"]').forEach(el => el.classList.add('hidden'));
        document.getElementById(`scan-tab-${tab}`)?.classList.remove('hidden');
        document.querySelectorAll('.tabs .tab').forEach(el => el.classList.remove('active'));
        document.querySelector(`.tab[data-tab="${tab}"]`)?.classList.add('active');
    },

    _renderFindings(findings) {
        if (!findings || !findings.length) return '';
        return `<div style="margin-top:var(--space-4)"><h4 style="margin-bottom:0.5rem">Findings</h4>${findings.map(f => `
            <div style="padding:0.4rem 0;border-bottom:1px solid var(--surface-divider);font-size:var(--fs-sm)">
                <span class="badge badge-${f.severity}">${f.severity}</span>
                <span class="fw-medium" style="margin-left:0.5rem">${f.title}</span>
                <div class="text-muted" style="font-size:var(--fs-xs);margin-top:2px">${f.recommendation || f.description || ''}</div>
            </div>`).join('')}</div>`;
    },

    async portScan() {
        const target = document.getElementById('ps-target').value;
        const ports = document.getElementById('ps-ports').value;
        if (!target) return Toast.warning('Enter a target');
        document.getElementById('ps-results').innerHTML = '<div class="flex items-center gap-2"><div class="spinner"></div> Scanning...</div>';
        try {
            const r = await API.post('/api/v1/scanner/port-scan', { target, ports });
            document.getElementById('ps-results').innerHTML = `
                <div class="grid-3" style="margin-bottom:var(--space-4)">
                    <div class="card stat-card"><div class="stat-value text-accent">${r.open_count}</div><div class="stat-label">Open</div></div>
                    <div class="card stat-card"><div class="stat-value">${r.closed_count}</div><div class="stat-label">Closed</div></div>
                    <div class="card stat-card"><div class="stat-value">${r.duration_ms}ms</div><div class="stat-label">Duration</div></div>
                </div>
                ${r.open_ports?.length ? `<div class="table-container"><table class="data-table">
                    <thead><tr><th>Port</th><th>Service</th><th>State</th><th>Banner</th></tr></thead>
                    <tbody>${r.open_ports.map(p => `<tr><td class="fw-semibold">${p.port}</td><td>${p.service}</td><td><span class="badge badge-success">open</span></td><td class="text-mono text-muted" style="font-size:0.7rem">${p.banner || '—'}</td></tr>`).join('')}</tbody>
                </table></div>` : '<p class="text-muted">No open ports found</p>'}
                ${this._renderFindings(r.findings)}
            `;
        } catch (e) { document.getElementById('ps-results').innerHTML = ''; Toast.error(e.message); }
    },

    async dnsLookup() {
        const domain = document.getElementById('dns-domain').value;
        if (!domain) return Toast.warning('Enter a domain');
        document.getElementById('dns-results').innerHTML = '<div class="spinner"></div>';
        try {
            const r = await API.post('/api/v1/scanner/dns-lookup', { domain });
            document.getElementById('dns-results').innerHTML = `
                <div class="card"><div class="card-body">
                    <div class="flex items-center gap-3 flex-wrap" style="margin-bottom:var(--space-3)">
                        <span class="chip">${r.has_spf ? '✅ SPF' : '❌ No SPF'}</span>
                        <span class="chip">${r.has_dmarc ? '✅ DMARC' : '❌ No DMARC'}</span>
                    </div>
                    ${Object.entries(r.records || {}).map(([type, records]) => `
                        <div style="margin-bottom:0.8rem"><span class="badge badge-info">${type}</span>
                        <div class="text-mono" style="font-size:var(--fs-xs);margin-top:4px;color:var(--text-secondary)">${records.length ? records.join('<br>') : '<span class="text-muted">No records</span>'}</div></div>
                    `).join('')}
                </div></div>
                ${this._renderFindings(r.findings)}
            `;
        } catch (e) { document.getElementById('dns-results').innerHTML = ''; Toast.error(e.message); }
    },

    async sslCheck() {
        const host = document.getElementById('ssl-host').value;
        const port = parseInt(document.getElementById('ssl-port').value);
        if (!host) return Toast.warning('Enter a host');
        document.getElementById('ssl-results').innerHTML = '<div class="spinner"></div>';
        try {
            const r = await API.post('/api/v1/scanner/ssl-check', { host, port });
            if (r.error) { document.getElementById('ssl-results').innerHTML = `<div class="card"><p class="text-danger">${r.error}</p></div>`; return; }
            document.getElementById('ssl-results').innerHTML = `
                <div class="card"><div class="card-body">
                    <div class="grid-3" style="margin-bottom:var(--space-4)">
                        <div><span class="text-muted">Subject:</span><br>${r.subject?.commonName || '—'}</div>
                        <div><span class="text-muted">Issuer:</span><br>${r.issuer?.organizationName || '—'}</div>
                        <div><span class="text-muted">Days Left:</span><br><span class="${r.days_remaining < 30 ? 'text-danger' : 'text-success'}">${r.days_remaining}</span></div>
                    </div>
                    <div class="grid-2" style="font-size:var(--fs-sm)">
                        <div><span class="text-muted">Protocol:</span> ${r.protocol_version || '—'}</div>
                        <div><span class="text-muted">Cipher:</span> ${r.cipher || '—'}</div>
                        <div><span class="text-muted">Valid From:</span> ${r.not_before || '—'}</div>
                        <div><span class="text-muted">Valid To:</span> ${r.not_after || '—'}</div>
                        <div><span class="text-muted">Expired:</span> <span class="${r.is_expired ? 'text-danger' : 'text-success'}">${r.is_expired ? 'Yes' : 'No'}</span></div>
                    </div>
                    ${r.san?.length ? `<div style="margin-top:var(--space-3)"><span class="text-muted">SANs:</span><div style="font-size:var(--fs-xs)">${r.san.join(', ')}</div></div>` : ''}
                </div></div>
                ${this._renderFindings(r.findings)}
            `;
        } catch (e) { document.getElementById('ssl-results').innerHTML = ''; Toast.error(e.message); }
    },

    async httpHeaders() {
        const url = document.getElementById('http-url').value;
        if (!url) return Toast.warning('Enter a URL');
        document.getElementById('http-results').innerHTML = '<div class="spinner"></div>';
        try {
            const r = await API.post('/api/v1/scanner/http-headers', { url });
            document.getElementById('http-results').innerHTML = `
                <div class="card"><div class="card-body">
                    <div class="flex items-center gap-3" style="margin-bottom:var(--space-4)">
                        <span class="badge badge-${r.status_code < 400 ? 'success' : 'danger'}">HTTP ${r.status_code}</span>
                        <span>Security Score: <b class="${r.security_score >= 70 ? 'text-success' : r.security_score >= 40 ? 'text-warning' : 'text-danger'}">${r.security_score}%</b></span>
                    </div>
                    <div class="progress-bar" style="margin-bottom:var(--space-4)"><div class="progress-bar-fill" style="width:${r.security_score}%"></div></div>
                    <div class="grid-2">
                        <div><h4 style="color:var(--color-success);margin-bottom:0.5rem">✅ Present (${r.security_headers_present?.length || 0})</h4>${(r.security_headers_present || []).map(h => `<div class="chip" style="margin:2px">${h.header}</div>`).join('')}</div>
                        <div><h4 style="color:var(--color-danger);margin-bottom:0.5rem">❌ Missing (${r.security_headers_missing?.length || 0})</h4>${(r.security_headers_missing || []).map(h => `<div class="chip" style="margin:2px;border-color:var(--color-danger)">${h}</div>`).join('')}</div>
                    </div>
                </div></div>
                ${this._renderFindings(r.findings)}
            `;
        } catch (e) { document.getElementById('http-results').innerHTML = ''; Toast.error(e.message); }
    },

    async whois() {
        const domain = document.getElementById('whois-domain').value;
        if (!domain) return Toast.warning('Enter a domain');
        document.getElementById('whois-results').innerHTML = '<div class="spinner"></div>';
        try {
            const r = await API.post('/api/v1/scanner/whois', { domain });
            document.getElementById('whois-results').innerHTML = `<div class="card"><div class="card-body" style="font-size:var(--fs-sm)">
                <div class="grid-2" style="gap:1rem">
                    <div><span class="text-muted">Registrar:</span><br>${r.registrar || '—'}</div>
                    <div><span class="text-muted">Registrant:</span><br>${r.registrant || '—'}</div>
                    <div><span class="text-muted">Created:</span><br>${r.creation_date || '—'}</div>
                    <div><span class="text-muted">Expires:</span><br>${r.expiration_date || '—'}</div>
                    <div><span class="text-muted">Country:</span><br>${r.country || '—'}</div>
                    <div><span class="text-muted">Name Servers:</span><br>${(r.name_servers || []).join(', ') || '—'}</div>
                </div>
            </div></div>`;
        } catch (e) { document.getElementById('whois-results').innerHTML = ''; Toast.error(e.message); }
    },

    async ping() {
        const target = document.getElementById('ping-target').value;
        const count = parseInt(document.getElementById('ping-count').value) || 4;
        if (!target) return Toast.warning('Enter a target');
        document.getElementById('ping-results').innerHTML = '<div class="spinner"></div>';
        try {
            const r = await API.post('/api/v1/scanner/ping', { target, count });
            document.getElementById('ping-results').innerHTML = `<div class="card"><div class="card-body">
                <div class="grid-3" style="margin-bottom:var(--space-3)">
                    <div class="stat-card" style="padding:0.5rem"><div class="stat-value" style="font-size:var(--fs-xl);color:${r.reachable ? 'var(--color-success)' : 'var(--color-danger)'}">${r.reachable ? '✅' : '❌'}</div><div class="stat-label">${r.reachable ? 'Reachable' : 'Unreachable'}</div></div>
                    <div class="stat-card" style="padding:0.5rem"><div class="stat-value" style="font-size:var(--fs-xl)">${r.avg_latency_ms != null ? r.avg_latency_ms + 'ms' : '—'}</div><div class="stat-label">Avg Latency</div></div>
                    <div class="stat-card" style="padding:0.5rem"><div class="stat-value" style="font-size:var(--fs-xl)">${r.packet_loss_percent != null ? r.packet_loss_percent + '%' : '—'}</div><div class="stat-label">Packet Loss</div></div>
                </div>
                <pre style="font-size:var(--fs-xs);max-height:300px;overflow:auto;color:var(--text-secondary)">${r.output || ''}</pre>
            </div></div>`;
        } catch (e) { document.getElementById('ping-results').innerHTML = ''; Toast.error(e.message); }
    },

    async traceroute() {
        const target = document.getElementById('trace-target').value;
        if (!target) return Toast.warning('Enter a target');
        document.getElementById('trace-results').innerHTML = '<div class="flex items-center gap-2"><div class="spinner"></div> Tracing route (this may take a minute)...</div>';
        try {
            const r = await API.post('/api/v1/scanner/traceroute', { target });
            document.getElementById('trace-results').innerHTML = `<div class="card"><div class="card-body">
                <p class="text-muted" style="margin-bottom:0.5rem">${r.total_hops || 0} hops to ${target}</p>
                <pre style="font-size:var(--fs-xs);max-height:400px;overflow:auto;color:var(--text-secondary)">${r.output || ''}</pre>
            </div></div>`;
        } catch (e) { document.getElementById('trace-results').innerHTML = ''; Toast.error(e.message); }
    },
};
