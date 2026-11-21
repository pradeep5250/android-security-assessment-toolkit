/**
 * ASAT — ADB Terminal Page
 */
const AdbPage = {
    async render() {
        const content = document.getElementById('page-content');
        content.innerHTML = `
            <div class="animate-fadeIn">
                <div class="page-header">
                    <div>
                        <h1>ADB Terminal</h1>
                        <p class="page-description">Device interaction, logcat viewer, and package management</p>
                    </div>
                </div>

                <!-- Device Selector -->
                <div class="card" style="margin-bottom:var(--space-4)">
                    <div class="flex items-center gap-4 flex-wrap">
                        <div class="form-group" style="flex:1;min-width:200px">
                            <label class="form-label">Select Device</label>
                            <select class="form-select" id="adb-device-select">
                                <option value="">Loading devices...</option>
                            </select>
                        </div>
                        <button class="btn" onclick="AdbPage.refreshDevices()" style="margin-top:auto">🔄 Refresh</button>
                        <button class="btn btn-primary" onclick="AdbPage.getDeviceInfo()" style="margin-top:auto">ℹ️ Device Info</button>
                        <button class="btn" onclick="AdbPage.takeScreenshot()" style="margin-top:auto">📸 Screenshot</button>
                    </div>
                </div>

                <!-- Tabs -->
                <div class="tabs">
                    <button class="tab active" data-tab="logcat" onclick="AdbPage.switchTab('logcat')">📋 Logcat</button>
                    <button class="tab" data-tab="packages" onclick="AdbPage.switchTab('packages')">📦 Packages</button>
                    <button class="tab" data-tab="services" onclick="AdbPage.switchTab('services')">⚙️ Services</button>
                    <button class="tab" data-tab="security" onclick="AdbPage.switchTab('security')">🔒 Security</button>
                </div>

                <!-- Tab Content -->
                <div id="adb-tab-logcat">
                    <div class="flex gap-3" style="margin-bottom:var(--space-3)">
                        <button class="btn btn-sm" onclick="AdbPage.loadLogcat()">📥 Load Logcat</button>
                        <button class="btn btn-sm btn-ghost" onclick="LogViewer.clear('adb-logcat')">🗑️ Clear</button>
                    </div>
                    <div id="adb-logcat"></div>
                </div>

                <div id="adb-tab-packages" class="hidden">
                    <div class="flex items-center gap-3" style="margin-bottom:var(--space-3)">
                        <button class="btn btn-sm" onclick="AdbPage.loadPackages(false)">📱 User Apps</button>
                        <button class="btn btn-sm" onclick="AdbPage.loadPackages(true)">📦 All Apps</button>
                        <div class="search-box" style="flex:1;max-width:300px">
                            <span class="search-icon">🔎</span>
                            <input type="text" placeholder="Filter packages..." id="pkg-filter" oninput="AdbPage.filterPackages()">
                        </div>
                    </div>
                    <div id="packages-list"></div>
                </div>

                <div id="adb-tab-services" class="hidden">
                    <button class="btn btn-sm" onclick="AdbPage.loadServices()" style="margin-bottom:var(--space-3)">🔄 Load Services</button>
                    <div id="services-list"></div>
                </div>

                <div id="adb-tab-security" class="hidden">
                    <button class="btn btn-sm btn-primary" onclick="AdbPage.quickSecurity()" style="margin-bottom:var(--space-3)">🔍 Quick Security Check</button>
                    <div id="security-results"></div>
                </div>
            </div>
        `;

        LogViewer.create('adb-logcat', { title: 'ADB Logcat', height: '350px' });
        this.refreshDevices();
    },

    async refreshDevices() {
        try {
            const data = await API.get('/api/v1/adb/devices');
            const select = document.getElementById('adb-device-select');
            if (data.devices && data.devices.length > 0) {
                select.innerHTML = data.devices.map(d =>
                    `<option value="${d.serial}">${d.serial} (${d.status})</option>`
                ).join('');
            } else {
                select.innerHTML = '<option value="">No devices connected</option>';
            }
        } catch (e) {
            document.getElementById('adb-device-select').innerHTML = '<option value="">ADB unavailable</option>';
        }
    },

    getSerial() {
        return document.getElementById('adb-device-select')?.value;
    },

    switchTab(tab) {
        document.querySelectorAll('[id^="adb-tab-"]').forEach(el => el.classList.add('hidden'));
        document.getElementById(`adb-tab-${tab}`)?.classList.remove('hidden');
        document.querySelectorAll('.tabs .tab').forEach(el => el.classList.remove('active'));
        document.querySelector(`.tab[data-tab="${tab}"]`)?.classList.add('active');
    },

    async getDeviceInfo() {
        const serial = this.getSerial();
        if (!serial) return Toast.warning('Select a device first');
        try {
            const info = await API.get(`/api/v1/adb/device/${serial}/info`);
            Modal.show('📱 Device Info', `<pre style="font-size:0.8rem;max-height:400px;overflow:auto;color:var(--text-secondary)">${JSON.stringify(info, null, 2)}</pre>`, { width: '600px' });
        } catch (e) { Toast.error(e.message); }
    },

    async takeScreenshot() {
        const serial = this.getSerial();
        if (!serial) return Toast.warning('Select a device first');
        try {
            Toast.info('Capturing screenshot...');
            const blob = await API.get(`/api/v1/adb/device/${serial}/screenshot`);
            const url = URL.createObjectURL(blob);
            Modal.show('📸 Screenshot', `<img src="${url}" style="max-width:100%;border-radius:8px">`, { width: '500px' });
        } catch (e) { Toast.error(e.message); }
    },

    async loadLogcat() {
        const serial = this.getSerial();
        if (!serial) return Toast.warning('Select a device first');
        try {
            LogViewer.clear('adb-logcat');
            Toast.info('Loading logcat...');
            const data = await API.get(`/api/v1/adb/device/${serial}/logcat?lines=300`);
            LogViewer.addLines('adb-logcat', data.content);
            Toast.success(`Loaded ${data.lines} log lines`);
        } catch (e) { Toast.error(e.message); }
    },

    _allPackages: [],

    async loadPackages(includeSystem) {
        const serial = this.getSerial();
        if (!serial) return Toast.warning('Select a device first');
        try {
            const data = await API.get(`/api/v1/adb/device/${serial}/packages?include_system=${includeSystem}`);
            this._allPackages = data.packages || [];
            this._renderPackages(this._allPackages);
            Toast.success(`Loaded ${data.total} packages`);
        } catch (e) { Toast.error(e.message); }
    },

    _renderPackages(packages) {
        const container = document.getElementById('packages-list');
        if (!packages.length) {
            container.innerHTML = '<p class="text-muted">No packages found</p>';
            return;
        }
        container.innerHTML = `
            <div class="table-container"><table class="data-table">
                <thead><tr><th>Package Name</th><th>APK Path</th><th>Actions</th></tr></thead>
                <tbody>${packages.map(p => `
                    <tr data-pkg="${p.package_name}">
                        <td class="text-mono" style="font-size:var(--fs-xs)">${p.package_name}</td>
                        <td class="text-muted" style="font-size:var(--fs-xs);max-width:300px;overflow:hidden;text-overflow:ellipsis">${p.apk_path || '—'}</td>
                        <td><button class="btn btn-sm btn-danger" onclick="AdbPage.uninstall('${p.package_name}')">Uninstall</button></td>
                    </tr>
                `).join('')}</tbody>
            </table></div>
        `;
    },

    filterPackages() {
        const q = document.getElementById('pkg-filter')?.value.toLowerCase() || '';
        const filtered = this._allPackages.filter(p => p.package_name.toLowerCase().includes(q));
        this._renderPackages(filtered);
    },

    async uninstall(pkg) {
        const serial = this.getSerial();
        Modal.confirm('Uninstall Package', `Remove ${pkg}?`, async () => {
            try {
                await API.delete(`/api/v1/adb/device/${serial}/package/${pkg}`);
                Toast.success(`Uninstalled ${pkg}`);
                this.loadPackages(false);
            } catch (e) { Toast.error(e.message); }
        });
    },

    async loadServices() {
        const serial = this.getSerial();
        if (!serial) return Toast.warning('Select a device first');
        try {
            const data = await API.get(`/api/v1/adb/device/${serial}/services`);
            document.getElementById('services-list').innerHTML = `
                <p class="text-muted" style="margin-bottom:0.5rem">${data.count} running services</p>
                <div style="max-height:400px;overflow:auto;font-family:var(--font-mono);font-size:var(--fs-xs)">
                    ${(data.services || []).map(s => `<div style="padding:3px 0;border-bottom:1px solid var(--surface-divider)">${s}</div>`).join('')}
                </div>`;
        } catch (e) { Toast.error(e.message); }
    },

    async quickSecurity() {
        const serial = this.getSerial();
        if (!serial) return Toast.warning('Select a device first');
        try {
            Toast.info('Running security check...');
            const data = await API.get(`/api/v1/adb/device/${serial}/security`);
            document.getElementById('security-results').innerHTML = `
                <div class="grid-3" style="margin-bottom:var(--space-4)">
                    <div class="card stat-card"><div class="stat-value" style="color:${data.is_rooted ? 'var(--severity-critical)' : 'var(--color-success)'}">${data.is_rooted ? '⚠️' : '✅'}</div><div class="stat-label">${data.is_rooted ? 'ROOTED' : 'Not Rooted'}</div></div>
                    <div class="card stat-card"><div class="stat-value" style="color:${data.developer_options_enabled ? 'var(--severity-medium)' : 'var(--color-success)'}">${data.developer_options_enabled ? '⚠️' : '✅'}</div><div class="stat-label">Dev Options ${data.developer_options_enabled ? 'ON' : 'OFF'}</div></div>
                    <div class="card stat-card"><div class="stat-value text-accent">${data.android_version || '—'}</div><div class="stat-label">Android Version</div></div>
                </div>
                ${(data.findings || []).map(f => `
                    <div style="padding:0.5rem 0;border-bottom:1px solid var(--surface-divider);font-size:var(--fs-sm)">
                        <span class="badge badge-${f.severity}">${f.severity}</span>
                        <span class="fw-medium" style="margin-left:0.5rem">${f.title}</span>
                        <p class="text-muted" style="margin-top:2px;font-size:var(--fs-xs)">${f.description}</p>
                    </div>
                `).join('')}
            `;
        } catch (e) { Toast.error(e.message); }
    },
};
