/**
 * ASAT — Main Application
 * SPA router, toast system, and initialization.
 */

// ── Toast Notification System ─────────────────────────────────────────────────

const Toast = {
    _container: null,

    _getContainer() {
        if (!this._container) {
            this._container = document.getElementById('toast-container');
        }
        return this._container;
    },

    show(type, title, message = '', duration = 4000) {
        const container = this._getContainer();
        const icons = { success: '✅', error: '❌', warning: '⚠️', info: 'ℹ️' };
        const id = 'toast-' + Date.now();

        const toast = document.createElement('div');
        toast.className = `toast ${type}`;
        toast.id = id;
        toast.innerHTML = `
            <span class="toast-icon">${icons[type] || 'ℹ️'}</span>
            <div class="toast-body">
                <div class="toast-title">${title}</div>
                ${message ? `<div class="toast-message">${message}</div>` : ''}
            </div>
            <button class="toast-close" onclick="Toast.dismiss('${id}')">&times;</button>
        `;

        container.appendChild(toast);

        // Auto-dismiss
        if (duration > 0) {
            setTimeout(() => this.dismiss(id), duration);
        }
    },

    dismiss(id) {
        const el = document.getElementById(id);
        if (!el) return;
        el.classList.add('toast-exit');
        setTimeout(() => el.remove(), 300);
    },

    success(msg) { this.show('success', msg); },
    error(msg) { this.show('error', msg, '', 6000); },
    warning(msg) { this.show('warning', msg); },
    info(msg) { this.show('info', msg); },
};


// ── SPA Router ─────────────────────────────────────────────────────────────────

const Router = {
    routes: {
        'dashboard':    { page: DashboardPage, title: 'Dashboard' },
        'devices':      { page: DevicesPage,   title: 'Devices' },
        'adb':          { page: AdbPage,       title: 'ADB Terminal' },
        'scanner':      { page: ScannerPage,   title: 'Network Scanner' },
        'apk-analysis': { page: ApkPage,       title: 'APK Analysis' },
        'reports':      { page: ReportsPage,   title: 'Reports' },
        'settings':     { page: SettingsPage,   title: 'Settings' },
    },

    currentPage: null,

    init() {
        window.addEventListener('hashchange', () => this.navigate());
        this.navigate();
    },

    navigate() {
        const hash = window.location.hash.replace('#', '') || 'dashboard';
        const route = this.routes[hash];

        if (!route) {
            window.location.hash = 'dashboard';
            return;
        }

        // Update active nav item
        document.querySelectorAll('.nav-item').forEach(item => {
            item.classList.toggle('active', item.dataset.page === hash);
        });

        // Update page title
        const titleEl = document.getElementById('page-title');
        if (titleEl) titleEl.textContent = route.title;
        document.title = `ASAT — ${route.title}`;

        // Render page
        this.currentPage = hash;
        route.page.render();
    },
};


// ── Application Initialization ────────────────────────────────────────────────

const App = {
    async init() {
        // Initialize auth
        Auth.init();

        if (Auth.isAuthenticated()) {
            this.showApp();
        } else {
            this.showLogin();
        }

        // Hide loading screen
        const loading = document.getElementById('app-loading');
        if (loading) {
            loading.classList.add('fade-out');
            setTimeout(() => loading.remove(), 500);
        }

        // Event listeners
        this.bindEvents();
    },

    showLogin() {
        document.getElementById('login-page').classList.remove('hidden');
        document.getElementById('app-container').classList.add('hidden');
    },

    showApp() {
        document.getElementById('login-page').classList.add('hidden');
        document.getElementById('app-container').classList.remove('hidden');

        // Update user display
        const user = Auth.getUser();
        if (user) {
            document.getElementById('user-display-name').textContent = user.full_name || user.username;
            document.getElementById('user-display-role').textContent = user.role;
            document.getElementById('user-avatar').textContent = (user.username || 'A')[0].toUpperCase();
        }

        // Init router
        Router.init();

        // Connect WebSocket
        WS.connect('general');
    },

    bindEvents() {
        // Login form
        document.getElementById('login-form')?.addEventListener('submit', async (e) => {
            e.preventDefault();
            const btn = document.getElementById('login-submit');
            btn.disabled = true;
            btn.innerHTML = '<span class="spinner" style="width:16px;height:16px;border-width:2px"></span> Signing in...';

            try {
                const username = document.getElementById('login-username').value;
                const password = document.getElementById('login-password').value;
                await Auth.login(username, password);
                Toast.success('Welcome back!');
                this.showApp();
            } catch (e) {
                Toast.error(e.message);
            } finally {
                btn.disabled = false;
                btn.innerHTML = 'Sign In';
            }
        });

        // Register form
        document.getElementById('register-form')?.addEventListener('submit', async (e) => {
            e.preventDefault();
            const btn = document.getElementById('register-submit');
            btn.disabled = true;
            btn.innerHTML = '<span class="spinner" style="width:16px;height:16px;border-width:2px"></span> Creating...';

            try {
                const username = document.getElementById('reg-username').value;
                const email = document.getElementById('reg-email').value;
                const password = document.getElementById('reg-password').value;
                const fullName = document.getElementById('reg-fullname').value;
                await Auth.register(username, email, password, fullName);
                Toast.success('Account created! Welcome!');
                this.showApp();
            } catch (e) {
                Toast.error(e.message);
            } finally {
                btn.disabled = false;
                btn.innerHTML = 'Create Account';
            }
        });

        // Toggle login/register
        document.getElementById('show-register')?.addEventListener('click', (e) => {
            e.preventDefault();
            document.getElementById('login-form').classList.add('hidden');
            document.getElementById('register-form').classList.remove('hidden');
        });

        document.getElementById('show-login')?.addEventListener('click', (e) => {
            e.preventDefault();
            document.getElementById('register-form').classList.add('hidden');
            document.getElementById('login-form').classList.remove('hidden');
        });

        // Sidebar toggle
        document.getElementById('sidebar-toggle')?.addEventListener('click', () => {
            const sidebar = document.getElementById('sidebar');
            sidebar.classList.toggle('collapsed');
            const btn = document.getElementById('sidebar-toggle');
            btn.textContent = sidebar.classList.contains('collapsed') ? '▶' : '◀';
        });

        // User menu dropdown
        document.getElementById('user-menu-toggle')?.addEventListener('click', () => {
            document.getElementById('user-dropdown').classList.toggle('active');
        });

        // Close dropdown when clicking outside
        document.addEventListener('click', (e) => {
            if (!e.target.closest('#user-menu-toggle') && !e.target.closest('#user-dropdown')) {
                document.getElementById('user-dropdown')?.classList.remove('active');
            }
        });

        // Logout button
        document.getElementById('btn-logout')?.addEventListener('click', () => Auth.logout());

        // Profile button
        document.getElementById('btn-profile')?.addEventListener('click', () => {
            window.location.hash = 'settings';
            document.getElementById('user-dropdown')?.classList.remove('active');
        });
    },
};

// ── Start the application ─────────────────────────────────────────────────────
document.addEventListener('DOMContentLoaded', () => App.init());
