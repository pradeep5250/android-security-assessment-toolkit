/**
 * ASAT — WebSocket Client
 * Auto-reconnecting WebSocket with message routing.
 */

const WS = {
    _socket: null,
    _listeners: {},
    _reconnectTimer: null,
    _reconnectDelay: 2000,
    _maxReconnectDelay: 30000,
    _connected: false,

    connect(channel = 'general') {
        if (this._socket && this._socket.readyState === WebSocket.OPEN) return;

        const token = Auth.getAccessToken();
        if (!token) return;

        const protocol = location.protocol === 'https:' ? 'wss:' : 'ws:';
        const url = `${protocol}//${location.host}/ws?token=${token}&channel=${channel}`;

        try {
            this._socket = new WebSocket(url);

            this._socket.onopen = () => {
                this._connected = true;
                this._reconnectDelay = 2000;
                this._emit('connected', { channel });
                console.log(`[WS] Connected to ${channel}`);
            };

            this._socket.onmessage = (event) => {
                try {
                    const data = JSON.parse(event.data);
                    this._emit(data.type || 'message', data);
                } catch {
                    this._emit('message', { raw: event.data });
                }
            };

            this._socket.onclose = (event) => {
                this._connected = false;
                this._emit('disconnected', { code: event.code });
                console.log(`[WS] Disconnected (${event.code})`);

                // Auto-reconnect unless intentionally closed
                if (event.code !== 4001 && event.code !== 1000) {
                    this._scheduleReconnect(channel);
                }
            };

            this._socket.onerror = () => {
                this._emit('error', {});
            };
        } catch (e) {
            console.warn('[WS] Connection failed:', e);
        }
    },

    disconnect() {
        if (this._reconnectTimer) {
            clearTimeout(this._reconnectTimer);
            this._reconnectTimer = null;
        }
        if (this._socket) {
            this._socket.close(1000);
            this._socket = null;
        }
        this._connected = false;
    },

    send(type, data = {}) {
        if (this._socket && this._socket.readyState === WebSocket.OPEN) {
            this._socket.send(JSON.stringify({ type, ...data }));
        }
    },

    on(event, callback) {
        if (!this._listeners[event]) this._listeners[event] = [];
        this._listeners[event].push(callback);
    },

    off(event, callback) {
        if (!this._listeners[event]) return;
        this._listeners[event] = this._listeners[event].filter(cb => cb !== callback);
    },

    _emit(event, data) {
        const listeners = this._listeners[event] || [];
        listeners.forEach(cb => {
            try { cb(data); } catch (e) { console.error('[WS] Listener error:', e); }
        });
    },

    _scheduleReconnect(channel) {
        if (this._reconnectTimer) return;
        console.log(`[WS] Reconnecting in ${this._reconnectDelay / 1000}s...`);
        this._reconnectTimer = setTimeout(() => {
            this._reconnectTimer = null;
            this._reconnectDelay = Math.min(this._reconnectDelay * 1.5, this._maxReconnectDelay);
            this.connect(channel);
        }, this._reconnectDelay);
    },

    isConnected() {
        return this._connected;
    },
};
