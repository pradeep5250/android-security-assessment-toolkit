/**
 * ASAT — API Client
 * Fetch wrapper with JWT interceptor, error handling, and file helpers.
 */

const API = {
    baseUrl: '',

    /**
     * Core fetch wrapper with auth headers and error handling.
     */
    async request(endpoint, options = {}) {
        const url = `${this.baseUrl}${endpoint}`;
        const headers = options.headers || {};

        // Add auth token
        const token = Auth.getAccessToken();
        if (token) {
            headers['Authorization'] = `Bearer ${token}`;
        }

        // Add content type for JSON bodies
        if (options.body && !(options.body instanceof FormData)) {
            headers['Content-Type'] = 'application/json';
            if (typeof options.body === 'object') {
                options.body = JSON.stringify(options.body);
            }
        }

        try {
            const response = await fetch(url, { ...options, headers });

            // Handle 401 — try token refresh
            if (response.status === 401 && endpoint !== '/api/v1/auth/login' && endpoint !== '/api/v1/auth/refresh') {
                const refreshed = await Auth.refreshToken();
                if (refreshed) {
                    headers['Authorization'] = `Bearer ${Auth.getAccessToken()}`;
                    const retryResponse = await fetch(url, { ...options, headers });
                    return this._handleResponse(retryResponse);
                } else {
                    Auth.logout();
                    throw new Error('Session expired. Please log in again.');
                }
            }

            return this._handleResponse(response);
        } catch (error) {
            if (error.name === 'TypeError' && error.message.includes('fetch')) {
                throw new Error('Network error — server may be unreachable.');
            }
            throw error;
        }
    },

    async _handleResponse(response) {
        if (response.status === 204) return null;

        const contentType = response.headers.get('content-type') || '';

        if (!response.ok) {
            let errorMsg = `Error ${response.status}`;
            if (contentType.includes('application/json')) {
                const data = await response.json();
                errorMsg = data.detail || data.message || errorMsg;
            }
            throw new Error(errorMsg);
        }

        if (contentType.includes('application/json')) {
            return response.json();
        }
        if (contentType.includes('image/') || contentType.includes('application/pdf') || contentType.includes('application/octet-stream')) {
            return response.blob();
        }
        return response.text();
    },

    // ── Convenience Methods ──────────────────────────────────────────────

    get(endpoint) {
        return this.request(endpoint, { method: 'GET' });
    },

    post(endpoint, data) {
        return this.request(endpoint, { method: 'POST', body: data });
    },

    patch(endpoint, data) {
        return this.request(endpoint, { method: 'PATCH', body: data });
    },

    delete(endpoint) {
        return this.request(endpoint, { method: 'DELETE' });
    },

    /**
     * Upload a file via multipart/form-data.
     */
    async upload(endpoint, file, extraFields = {}) {
        const formData = new FormData();
        formData.append('apk', file); // Default field name
        for (const [key, value] of Object.entries(extraFields)) {
            formData.append(key, value);
        }
        return this.request(endpoint, { method: 'POST', body: formData });
    },

    /**
     * Download a file and trigger browser download.
     */
    async download(endpoint, filename) {
        const blob = await this.request(endpoint, { method: 'GET' });
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = filename || 'download';
        document.body.appendChild(a);
        a.click();
        document.body.removeChild(a);
        URL.revokeObjectURL(url);
    },
};
