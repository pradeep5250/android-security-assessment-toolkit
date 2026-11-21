/**
 * ASAT — Auth Module
 * JWT token storage, login/logout, and session management.
 */

const Auth = {
    _accessToken: null,
    _refreshTokenValue: null,
    _user: null,

    init() {
        this._accessToken = localStorage.getItem('asat_access_token');
        this._refreshTokenValue = localStorage.getItem('asat_refresh_token');
        const userData = localStorage.getItem('asat_user');
        if (userData) {
            try { this._user = JSON.parse(userData); } catch { this._user = null; }
        }
    },

    isAuthenticated() {
        return !!this._accessToken;
    },

    getAccessToken() {
        return this._accessToken;
    },

    getUser() {
        return this._user;
    },

    setTokens(accessToken, refreshToken) {
        this._accessToken = accessToken;
        this._refreshTokenValue = refreshToken;
        localStorage.setItem('asat_access_token', accessToken);
        localStorage.setItem('asat_refresh_token', refreshToken);
    },

    setUser(user) {
        this._user = user;
        localStorage.setItem('asat_user', JSON.stringify(user));
    },

    async login(username, password) {
        const data = await API.post('/api/v1/auth/login', { username, password });
        this.setTokens(data.access_token, data.refresh_token);

        // Fetch user profile
        const user = await API.get('/api/v1/auth/me');
        this.setUser(user);

        return user;
    },

    async register(username, email, password, fullName) {
        const body = { username, email, password };
        if (fullName) body.full_name = fullName;
        const user = await API.post('/api/v1/auth/register', body);
        // Auto-login after registration
        await this.login(username, password);
        return user;
    },

    async refreshToken() {
        if (!this._refreshTokenValue) return false;
        try {
            const data = await API.post('/api/v1/auth/refresh', {
                refresh_token: this._refreshTokenValue,
            });
            this.setTokens(data.access_token, data.refresh_token);
            return true;
        } catch {
            return false;
        }
    },

    logout() {
        this._accessToken = null;
        this._refreshTokenValue = null;
        this._user = null;
        localStorage.removeItem('asat_access_token');
        localStorage.removeItem('asat_refresh_token');
        localStorage.removeItem('asat_user');
        window.location.hash = '';
        window.location.reload();
    },
};
