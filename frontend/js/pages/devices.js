/**
 * ASAT — Devices Page
 */
const DevicesPage = {
    async render() {
        const content = document.getElementById('page-content');
        content.innerHTML = `
            <div class="animate-fadeIn">
                <div class="page-header">
                    <div>
                        <h1>Devices</h1>
                        <p class="page-description">Manage and audit connected Android devices</p>
                    </div>
                    <div class="page-actions">
                        <button class="btn btn-primary" onclick="DevicesPage.syncDevices()">📱 Sync ADB Devices</button>
                    </div>
                </div>

                <div id="devices-list" class="grid-auto">
                    <div class="empty-state"><div class="spinner-lg" style="margin:0 auto"></div><p class="text-muted" style="margin-top:1rem">Loading devices...</p></div>
                </div>
            </div>
        `;
        this.loadDevices();
    },

    async loadDevices() {
        try {
            const data = await API.get('/api/v1/devices/?per_page=50');
            const container = document.getElementById('devices-list');

            if (!data.devices || data.devices.length === 0) {
                container.innerHTML = `
                    <div class="empty-state" style="grid-column:1/-1">
                        <div class="empty-icon">📱</div>
                        <div class="empty-title">No Devices Found</div>
                        <div class="empty-text">Connect an Android device via USB and click "Sync ADB Devices"</div>
                        <button class="btn btn-primary" onclick="DevicesPage.syncDevices()">Sync Now</button>
                    </div>`;
                return;
            }

            container.innerHTML = data.devices.map(d => `
                <div class="card" style="cursor:pointer" onclick="DevicesPage.showDevice(${d.id})">
                    <div class="flex items-center justify-between" style="margin-bottom:var(--space-3)">
                        <div class="flex items-center gap-2">
                            <span class="status-dot ${d.status === 'online' ? 'online' : 'offline'}"></span>
                            <span class="fw-semibold">${d.nickname || d.model || d.serial}</span>
                        </div>
                        <span class="badge badge-${d.status === 'online' ? 'success' : 'info'}">${d.status}</span>
                    </div>
                    <div style="font-size:var(--fs-xs);color:var(--text-secondary);display:flex;flex-direction:column;gap:4px">
                        <div>📱 ${d.manufacturer || '—'} ${d.model || ''}</div>
                        <div>🤖 Android ${d.android_version || '—'}</div>
                        <div>🔒 Patch: ${d.security_patch || '—'}</div>
                        <div class="text-mono" style="font-size:0.7rem;color:var(--text-tertiary)">S/N: ${d.serial}</div>
                    </div>
                    <div style="margin-top:var(--space-3);display:flex;gap:var(--space-2)">
                        <button class="btn btn-sm" onclick="event.stopPropagation();DevicesPage.auditDevice(${d.id})">🔍 Audit</button>
                        <button class="btn btn-sm btn-ghost" onclick="event.stopPropagation();DevicesPage.deleteDevice(${d.id})">🗑️</button>
                    </div>
                </div>
            `).join('');

            document.getElementById('device-count-badge').textContent = data.total;
        } catch (e) {
            Toast.error('Failed to load devices: ' + e.message);
        }
    },

    async syncDevices() {
        try {
            Toast.info('Syncing devices via ADB...');
            const data = await API.post('/api/v1/devices/sync');
            Toast.success(`Synced ${data.synced} device(s)`);
            this.loadDevices();
        } catch (e) {
            Toast.error(e.message);
        }
    },

    async showDevice(id) {
        try {
            const device = await API.get(`/api/v1/devices/${id}`);
            const meta = device.metadata_json || {};
            Modal.show(`📱 ${device.model || device.serial}`, `
                <div style="display:grid;grid-template-columns:1fr 1fr;gap:0.8rem;font-size:var(--fs-sm)">
                    <div><span class="text-muted">Serial:</span><br><span class="text-mono">${device.serial}</span></div>
                    <div><span class="text-muted">Status:</span><br><span class="badge badge-${device.status === 'online' ? 'success' : 'info'}">${device.status}</span></div>
                    <div><span class="text-muted">Manufacturer:</span><br>${device.manufacturer || '—'}</div>
                    <div><span class="text-muted">Model:</span><br>${device.model || '—'}</div>
                    <div><span class="text-muted">Android:</span><br>${device.android_version || '—'}</div>
                    <div><span class="text-muted">SDK:</span><br>${device.sdk_version || '—'}</div>
                    <div><span class="text-muted">Security Patch:</span><br>${device.security_patch || '—'}</div>
                    <div><span class="text-muted">CPU:</span><br>${device.cpu_abi || '—'}</div>
                    <div><span class="text-muted">Display:</span><br>${device.display_resolution || '—'}</div>
                    <div><span class="text-muted">Battery:</span><br>${meta.battery_level ? meta.battery_level + '%' : '—'}</div>
                    <div><span class="text-muted">RAM:</span><br>${meta.total_ram ? (parseInt(meta.total_ram)/1024/1024).toFixed(0) + ' MB' : '—'}</div>
                    <div><span class="text-muted">Build:</span><br><span class="text-mono" style="font-size:0.7rem">${device.build_fingerprint || '—'}</span></div>
                </div>
            `, { width: '650px' });
        } catch (e) {
            Toast.error(e.message);
        }
    },

    async auditDevice(id) {
        try {
            Toast.info('Running security audit...');
            const result = await API.post(`/api/v1/devices/${id}/audit`);
            Modal.show(`🔒 Security Audit — ${result.serial}`, `
                <div style="text-align:center;margin-bottom:1.5rem">
                    <div style="font-size:2.5rem;font-weight:800;color:${result.risk_score >= 55 ? 'var(--severity-high)' : result.risk_score >= 30 ? 'var(--severity-medium)' : 'var(--severity-low)'}">${result.risk_score?.toFixed(0) || 0}</div>
                    <div style="font-size:0.85rem;color:var(--text-secondary)">Risk Score — ${result.risk_level || 'Unknown'}</div>
                </div>
                <div style="font-size:var(--fs-sm)">
                    ${(result.findings || []).map(f => `
                        <div style="padding:0.5rem 0;border-bottom:1px solid var(--surface-divider);display:flex;gap:0.5rem;align-items:flex-start">
                            <span class="badge badge-${f.severity}">${f.severity}</span>
                            <div>
                                <div class="fw-medium">${f.title}</div>
                                <div class="text-muted" style="font-size:var(--fs-xs)">${f.description || ''}</div>
                            </div>
                        </div>
                    `).join('') || '<p class="text-muted">No findings — device looks secure!</p>'}
                </div>
            `, { width: '650px' });
        } catch (e) {
            Toast.error(e.message);
        }
    },

    async deleteDevice(id) {
        Modal.confirm('Delete Device', 'Remove this device from tracking?', async () => {
            try {
                await API.delete(`/api/v1/devices/${id}`);
                Toast.success('Device removed');
                this.loadDevices();
            } catch (e) { Toast.error(e.message); }
        });
    },
};
