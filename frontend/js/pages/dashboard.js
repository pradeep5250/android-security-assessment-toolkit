/**
 * ASAT — Dashboard Page
 */
const DashboardPage = {
    async render() {
        const content = document.getElementById('page-content');
        content.innerHTML = `
            <div class="animate-fadeIn">
                <div class="page-header">
                    <div>
                        <h1>Security Dashboard</h1>
                        <p class="page-description">Overview of your security assessment environment</p>
                    </div>
                    <div class="page-actions">
                        <button class="btn" onclick="DashboardPage.refresh()">🔄 Refresh</button>
                    </div>
                </div>

                <!-- Stats Cards -->
                <div class="grid-4" id="stats-grid">
                    <div class="card stat-card">
                        <div class="stat-value" id="stat-devices">—</div>
                        <div class="stat-label">Devices</div>
                    </div>
                    <div class="card stat-card">
                        <div class="stat-value" id="stat-scans">—</div>
                        <div class="stat-label">Total Scans</div>
                    </div>
                    <div class="card stat-card">
                        <div class="stat-value" id="stat-reports">—</div>
                        <div class="stat-label">Reports</div>
                    </div>
                    <div class="card stat-card">
                        <div class="stat-value" id="stat-online">—</div>
                        <div class="stat-label">Online Devices</div>
                    </div>
                </div>

                <!-- Charts Row -->
                <div class="grid-2" style="margin-top:var(--space-6)">
                    <div class="card">
                        <div class="card-header">
                            <h3 class="card-title">Scan Activity</h3>
                        </div>
                        <div class="card-body" style="height:250px">
                            <canvas id="chart-scans"></canvas>
                        </div>
                    </div>
                    <div class="card">
                        <div class="card-header">
                            <h3 class="card-title">Severity Distribution</h3>
                        </div>
                        <div class="card-body" style="height:250px">
                            <canvas id="chart-severity"></canvas>
                        </div>
                    </div>
                </div>

                <!-- Recent Activity & Quick Actions -->
                <div class="grid-2" style="margin-top:var(--space-6)">
                    <div class="card">
                        <div class="card-header">
                            <h3 class="card-title">Recent Activity</h3>
                        </div>
                        <div class="card-body" id="recent-activity">
                            <div class="empty-state">
                                <div class="empty-icon">📋</div>
                                <div class="empty-text">No recent activity yet</div>
                            </div>
                        </div>
                    </div>
                    <div class="card">
                        <div class="card-header">
                            <h3 class="card-title">Quick Actions</h3>
                        </div>
                        <div class="card-body">
                            <div style="display:flex;flex-direction:column;gap:var(--space-3)">
                                <a href="#devices" class="btn" style="justify-content:flex-start">📱 Sync Devices</a>
                                <a href="#scanner" class="btn" style="justify-content:flex-start">🔍 Port Scan</a>
                                <a href="#apk-analysis" class="btn" style="justify-content:flex-start">📦 Analyze APK</a>
                                <a href="#adb" class="btn" style="justify-content:flex-start">💻 ADB Terminal</a>
                                <a href="#reports" class="btn" style="justify-content:flex-start">📄 Generate Report</a>
                            </div>
                        </div>
                    </div>
                </div>

                <!-- ADB Status -->
                <div class="card" style="margin-top:var(--space-6)">
                    <div class="card-header">
                        <h3 class="card-title">System Status</h3>
                    </div>
                    <div class="card-body">
                        <div style="display:flex;gap:var(--space-8);flex-wrap:wrap">
                            <div class="flex items-center gap-2">
                                <span class="status-dot" id="status-api"></span>
                                <span style="font-size:var(--fs-sm)">API Server</span>
                            </div>
                            <div class="flex items-center gap-2">
                                <span class="status-dot" id="status-adb"></span>
                                <span style="font-size:var(--fs-sm)">ADB</span>
                            </div>
                            <div class="flex items-center gap-2">
                                <span class="status-dot" id="status-ws"></span>
                                <span style="font-size:var(--fs-sm)">WebSocket</span>
                            </div>
                            <div class="flex items-center gap-2">
                                <span class="status-dot" id="status-db"></span>
                                <span style="font-size:var(--fs-sm)">Database</span>
                            </div>
                        </div>
                    </div>
                </div>
            </div>
        `;

        this.loadStats();
    },

    async loadStats() {
        try {
            const stats = await API.get('/api/v1/stats');

            document.getElementById('stat-devices').textContent = stats.devices?.total || 0;
            document.getElementById('stat-scans').textContent = stats.scans?.total || 0;
            document.getElementById('stat-reports').textContent = stats.reports?.total || 0;
            document.getElementById('stat-online').textContent = stats.devices?.online || 0;

            // Render activity
            const actContainer = document.getElementById('recent-activity');
            if (stats.recent_activity && stats.recent_activity.length > 0) {
                actContainer.innerHTML = stats.recent_activity.map(a => `
                    <div style="display:flex;justify-content:space-between;padding:0.5rem 0;border-bottom:1px solid var(--surface-divider);font-size:var(--fs-sm)">
                        <div>
                            <span class="text-muted">${a.username || 'system'}</span>
                            <span style="margin-left:0.5rem">${a.action}</span>
                        </div>
                        <span class="text-muted" style="font-size:var(--fs-xs)">${new Date(a.timestamp).toLocaleTimeString()}</span>
                    </div>
                `).join('');
            }

            // Charts with sample data
            Charts.bar('chart-scans',
                ['Port Scan', 'DNS', 'SSL', 'HTTP', 'APK', 'Audit'],
                [{ label: 'Scans', data: [3, 5, 2, 4, 1, 2], backgroundColor: 'rgba(0, 212, 255, 0.6)', borderRadius: 6 }]
            );

            Charts.donut('chart-severity',
                ['Critical', 'High', 'Medium', 'Low', 'Info'],
                [2, 5, 8, 12, 4]
            );

            // System status
            document.getElementById('status-api').className = 'status-dot online';
            document.getElementById('status-db').className = 'status-dot online';
            document.getElementById('status-ws').className = WS.isConnected() ? 'status-dot online' : 'status-dot offline';

            // Check ADB
            try {
                const adb = await API.get('/api/v1/adb/status');
                document.getElementById('status-adb').className = adb.available ? 'status-dot online' : 'status-dot warning';
            } catch {
                document.getElementById('status-adb').className = 'status-dot offline';
            }

        } catch (e) {
            Toast.error('Failed to load dashboard stats: ' + e.message);
        }
    },

    async refresh() {
        Toast.info('Refreshing dashboard...');
        await this.loadStats();
        Toast.success('Dashboard refreshed');
    },
};
