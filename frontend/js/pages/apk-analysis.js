/**
 * ASAT — APK Analysis Page
 */
const ApkPage = {
    async render() {
        const content = document.getElementById('page-content');
        content.innerHTML = `
            <div class="animate-fadeIn">
                <div class="page-header">
                    <div><h1>APK Analysis</h1><p class="page-description">Upload and analyze Android APK files for security issues</p></div>
                </div>

                <!-- Upload -->
                <div class="card" id="apk-upload-card">
                    <div class="card-body" style="text-align:center;padding:var(--space-10)">
                        <div style="font-size:3rem;margin-bottom:var(--space-4)">📦</div>
                        <h3 style="margin-bottom:var(--space-2)">Drop APK file here or click to upload</h3>
                        <p class="text-muted" style="margin-bottom:var(--space-6)">Supports .apk files up to 500MB</p>
                        <input type="file" id="apk-file-input" accept=".apk" style="display:none" onchange="ApkPage.analyzeFile()">
                        <button class="btn btn-primary btn-lg" onclick="document.getElementById('apk-file-input').click()">
                            📂 Select APK File
                        </button>
                    </div>
                </div>

                <!-- Progress -->
                <div id="apk-progress" class="hidden" style="margin-top:var(--space-4)">
                    <div class="card">
                        <div class="card-body" style="text-align:center">
                            <div class="spinner-lg" style="margin:0 auto var(--space-4)"></div>
                            <p>Analyzing APK... This may take a moment.</p>
                        </div>
                    </div>
                </div>

                <!-- Results -->
                <div id="apk-results" style="margin-top:var(--space-4)"></div>
            </div>
        `;

        // Drag and drop
        const card = document.getElementById('apk-upload-card');
        card.addEventListener('dragover', (e) => { e.preventDefault(); card.style.borderColor = 'var(--accent-primary)'; });
        card.addEventListener('dragleave', () => { card.style.borderColor = ''; });
        card.addEventListener('drop', (e) => {
            e.preventDefault();
            card.style.borderColor = '';
            const file = e.dataTransfer.files[0];
            if (file && file.name.endsWith('.apk')) {
                document.getElementById('apk-file-input').files = e.dataTransfer.files;
                this.analyzeFile();
            } else {
                Toast.warning('Please drop a valid .apk file');
            }
        });
    },

    async analyzeFile() {
        const input = document.getElementById('apk-file-input');
        const file = input.files[0];
        if (!file) return;

        document.getElementById('apk-progress').classList.remove('hidden');
        document.getElementById('apk-results').innerHTML = '';

        try {
            const formData = new FormData();
            formData.append('apk', file);

            const result = await API.request('/api/v1/apk/analyze', {
                method: 'POST',
                body: formData,
            });

            document.getElementById('apk-progress').classList.add('hidden');
            this._renderResults(result);
        } catch (e) {
            document.getElementById('apk-progress').classList.add('hidden');
            Toast.error('Analysis failed: ' + e.message);
        }
    },

    _renderResults(r) {
        const perms = r.permissions || {};
        const findings = r.findings || [];

        document.getElementById('apk-results').innerHTML = `
            <!-- Summary -->
            <div class="grid-4" style="margin-bottom:var(--space-4)">
                <div class="card stat-card">
                    <div class="stat-value" style="color:${r.risk_score >= 55 ? 'var(--severity-high)' : r.risk_score >= 30 ? 'var(--severity-medium)' : 'var(--severity-low)'}">${r.risk_score?.toFixed(0) || 0}</div>
                    <div class="stat-label">Risk Score</div>
                </div>
                <div class="card stat-card">
                    <div class="stat-value">${findings.length}</div>
                    <div class="stat-label">Findings</div>
                </div>
                <div class="card stat-card">
                    <div class="stat-value">${perms.dangerous_count || 0}</div>
                    <div class="stat-label">Dangerous Perms</div>
                </div>
                <div class="card stat-card">
                    <div class="stat-value">${r.file_size_mb || '—'}</div>
                    <div class="stat-label">Size (MB)</div>
                </div>
            </div>

            <!-- App Info -->
            <div class="card" style="margin-bottom:var(--space-4)">
                <div class="card-header"><h3 class="card-title">📱 Application Info</h3></div>
                <div class="card-body">
                    <div class="grid-3" style="font-size:var(--fs-sm)">
                        <div><span class="text-muted">Package:</span><br><span class="text-mono">${r.package_name || r.file_name}</span></div>
                        <div><span class="text-muted">App Name:</span><br>${r.app_name || '—'}</div>
                        <div><span class="text-muted">Version:</span><br>${r.version_name || '—'} (${r.version_code || '—'})</div>
                        <div><span class="text-muted">Min SDK:</span><br>API ${r.min_sdk || '—'}</div>
                        <div><span class="text-muted">Target SDK:</span><br>API ${r.target_sdk || '—'}</div>
                        <div><span class="text-muted">File:</span><br>${r.file_name}</div>
                    </div>
                </div>
            </div>

            <!-- Permissions -->
            <div class="card" style="margin-bottom:var(--space-4)">
                <div class="card-header"><h3 class="card-title">🔐 Permissions (${perms.total || 0})</h3></div>
                <div class="card-body">
                    ${perms.dangerous?.length ? `
                        <h4 style="color:var(--color-danger);margin-bottom:0.5rem">⚠️ Dangerous Permissions (${perms.dangerous_count})</h4>
                        <div class="table-container" style="margin-bottom:var(--space-4)"><table class="data-table">
                            <thead><tr><th>Permission</th><th>Category</th><th>Severity</th><th>Description</th></tr></thead>
                            <tbody>${perms.dangerous.map(p => `
                                <tr>
                                    <td class="text-mono" style="font-size:0.7rem">${p.permission.split('.').pop()}</td>
                                    <td>${p.category}</td>
                                    <td><span class="badge badge-${p.severity}">${p.severity}</span></td>
                                    <td class="text-muted">${p.description}</td>
                                </tr>
                            `).join('')}</tbody>
                        </table></div>
                    ` : ''}
                    ${perms.normal?.length ? `
                        <details><summary class="text-muted" style="cursor:pointer;font-size:var(--fs-sm)">Normal Permissions (${perms.normal_count})</summary>
                        <div style="margin-top:0.5rem;font-size:var(--fs-xs);font-family:var(--font-mono);color:var(--text-secondary)">${perms.normal.map(p => p.split('.').pop()).join(', ')}</div></details>
                    ` : ''}
                </div>
            </div>

            <!-- Components -->
            ${r.activities || r.services || r.receivers || r.providers ? `
            <div class="card" style="margin-bottom:var(--space-4)">
                <div class="card-header"><h3 class="card-title">🧩 Components</h3></div>
                <div class="card-body">
                    <div class="grid-4" style="text-align:center;margin-bottom:var(--space-3)">
                        <div><span class="fw-bold text-accent">${r.activities?.total || 0}</span><br><span class="text-muted" style="font-size:var(--fs-xs)">Activities</span></div>
                        <div><span class="fw-bold text-accent">${r.services?.total || 0}</span><br><span class="text-muted" style="font-size:var(--fs-xs)">Services</span></div>
                        <div><span class="fw-bold text-accent">${r.receivers?.total || 0}</span><br><span class="text-muted" style="font-size:var(--fs-xs)">Receivers</span></div>
                        <div><span class="fw-bold text-accent">${r.providers?.total || 0}</span><br><span class="text-muted" style="font-size:var(--fs-xs)">Providers</span></div>
                    </div>
                </div>
            </div>` : ''}

            <!-- Findings -->
            ${findings.length ? `
            <div class="card">
                <div class="card-header"><h3 class="card-title">🔍 Security Findings (${findings.length})</h3></div>
                <div class="card-body">
                    ${findings.map((f, i) => `
                        <div style="padding:0.6rem 0;border-bottom:1px solid var(--surface-divider)">
                            <div class="flex items-center gap-2">
                                <span class="badge badge-${f.severity}">${f.severity}</span>
                                <span class="fw-medium">${f.title}</span>
                            </div>
                            <div class="text-muted" style="font-size:var(--fs-xs);margin-top:4px">${f.description || ''}</div>
                            ${f.recommendation ? `<div style="font-size:var(--fs-xs);color:var(--accent-primary);margin-top:4px">💡 ${f.recommendation}</div>` : ''}
                        </div>
                    `).join('')}
                </div>
            </div>` : ''}
        `;
    },
};
