/**
 * ASAT — Settings Page
 */
const SettingsPage = {
    async render() {
        const user = Auth.getUser();
        const content = document.getElementById('page-content');
        content.innerHTML = `
            <div class="animate-fadeIn">
                <div class="page-header">
                    <div><h1>Settings</h1><p class="page-description">Profile, system configuration, and preferences</p></div>
                </div>

                <div class="grid-2">
                    <!-- Profile -->
                    <div class="card">
                        <div class="card-header"><h3 class="card-title">👤 Profile</h3></div>
                        <div class="card-body">
                            <form id="profile-form" class="flex flex-col gap-4">
                                <div class="form-group">
                                    <label class="form-label">Username</label>
                                    <input class="form-input" value="${user?.username || ''}" disabled>
                                </div>
                                <div class="form-group">
                                    <label class="form-label">Email</label>
                                    <input class="form-input" id="settings-email" value="${user?.email || ''}">
                                </div>
                                <div class="form-group">
                                    <label class="form-label">Full Name</label>
                                    <input class="form-input" id="settings-fullname" value="${user?.full_name || ''}">
                                </div>
                                <div class="form-group">
                                    <label class="form-label">Role</label>
                                    <input class="form-input" value="${user?.role || ''}" disabled>
                                </div>
                                <button type="button" class="btn btn-primary" onclick="SettingsPage.updateProfile()">Save Changes</button>
                            </form>
                        </div>
                    </div>

                    <!-- Change Password -->
                    <div class="card">
                        <div class="card-header"><h3 class="card-title">🔒 Change Password</h3></div>
                        <div class="card-body">
                            <form class="flex flex-col gap-4">
                                <div class="form-group">
                                    <label class="form-label">New Password</label>
                                    <input class="form-input" type="password" id="settings-newpass" placeholder="Minimum 8 characters" minlength="8">
                                </div>
                                <div class="form-group">
                                    <label class="form-label">Confirm Password</label>
                                    <input class="form-input" type="password" id="settings-confirmpass" placeholder="Repeat password">
                                </div>
                                <button type="button" class="btn btn-primary" onclick="SettingsPage.changePassword()">Update Password</button>
                            </form>
                        </div>
                    </div>
                </div>

                <!-- System Info -->
                <div class="card" style="margin-top:var(--space-6)">
                    <div class="card-header"><h3 class="card-title">🖥️ System Information</h3></div>
                    <div class="card-body">
                        <div id="system-info">Loading...</div>
                    </div>
                </div>

                <!-- Danger Zone -->
                <div class="card" style="margin-top:var(--space-6);border-color:rgba(239,68,68,0.2)">
                    <div class="card-header"><h3 class="card-title" style="color:var(--color-danger)">⚠️ Danger Zone</h3></div>
                    <div class="card-body flex items-center justify-between">
                        <div>
                            <p class="fw-medium">Sign out of your account</p>
                            <p class="text-muted" style="font-size:var(--fs-xs)">You will need to log in again</p>
                        </div>
                        <button class="btn btn-danger" onclick="Auth.logout()">🚪 Logout</button>
                    </div>
                </div>
            </div>
        `;

        this.loadSystemInfo();
    },

    async updateProfile() {
        try {
            const updates = {};
            const email = document.getElementById('settings-email').value;
            const fullName = document.getElementById('settings-fullname').value;
            if (email) updates.email = email;
            if (fullName) updates.full_name = fullName;

            const user = await API.patch('/api/v1/auth/me', updates);
            Auth.setUser(user);
            Toast.success('Profile updated');
        } catch (e) { Toast.error(e.message); }
    },

    async changePassword() {
        const newPass = document.getElementById('settings-newpass').value;
        const confirm = document.getElementById('settings-confirmpass').value;
        if (!newPass || newPass.length < 8) return Toast.warning('Password must be at least 8 characters');
        if (newPass !== confirm) return Toast.warning('Passwords do not match');

        try {
            await API.patch('/api/v1/auth/me', { password: newPass });
            Toast.success('Password updated');
            document.getElementById('settings-newpass').value = '';
            document.getElementById('settings-confirmpass').value = '';
        } catch (e) { Toast.error(e.message); }
    },

    async loadSystemInfo() {
        try {
            const health = await API.get('/health');
            const adb = await API.get('/api/v1/adb/status').catch(() => ({ available: false }));

            document.getElementById('system-info').innerHTML = `
                <div class="grid-3" style="font-size:var(--fs-sm)">
                    <div><span class="text-muted">Application:</span><br>${health.app}</div>
                    <div><span class="text-muted">Version:</span><br>${health.version}</div>
                    <div><span class="text-muted">API Status:</span><br><span class="badge badge-success">Healthy</span></div>
                    <div><span class="text-muted">ADB:</span><br><span class="badge badge-${adb.available ? 'success' : 'warning'}">${adb.available ? 'Available' : 'Not Found'}</span></div>
                    <div><span class="text-muted">ADB Path:</span><br><span class="text-mono">${adb.adb_path || '—'}</span></div>
                    <div><span class="text-muted">WebSocket:</span><br><span class="badge badge-${WS.isConnected() ? 'success' : 'warning'}">${WS.isConnected() ? 'Connected' : 'Disconnected'}</span></div>
                </div>
            `;
        } catch (e) {
            document.getElementById('system-info').innerHTML = `<p class="text-danger">${e.message}</p>`;
        }
    },
};
