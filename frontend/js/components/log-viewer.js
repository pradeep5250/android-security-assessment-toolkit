/**
 * ASAT — Log Viewer Component
 * Renders logcat-style output with level coloring and filtering.
 */
const LogViewer = {
    create(containerId, options = {}) {
        const container = document.getElementById(containerId);
        if (!container) return;

        const height = options.height || '400px';
        container.innerHTML = `
            <div class="log-viewer">
                <div class="log-viewer-header">
                    <div class="flex items-center gap-3">
                        <span style="font-weight:600;font-size:0.85rem">📋 ${options.title || 'Log Output'}</span>
                        <select class="form-select" id="${containerId}-filter" style="width:auto;padding:0.25rem 0.5rem;font-size:0.75rem">
                            <option value="all">All Levels</option>
                            <option value="error">Error</option>
                            <option value="warn">Warning</option>
                            <option value="info">Info</option>
                            <option value="debug">Debug</option>
                            <option value="verbose">Verbose</option>
                        </select>
                    </div>
                    <div class="flex items-center gap-2">
                        <label style="font-size:0.75rem;color:var(--text-secondary);display:flex;align-items:center;gap:4px">
                            <input type="checkbox" id="${containerId}-autoscroll" checked> Auto-scroll
                        </label>
                        <button class="btn btn-sm btn-ghost" onclick="LogViewer.clear('${containerId}')">Clear</button>
                        <button class="btn btn-sm btn-ghost" onclick="LogViewer.copy('${containerId}')">Copy</button>
                    </div>
                </div>
                <div class="log-viewer-body" id="${containerId}-body" style="height:${height}"></div>
            </div>
        `;

        // Filter listener
        document.getElementById(`${containerId}-filter`).addEventListener('change', (e) => {
            this._applyFilter(containerId, e.target.value);
        });
    },

    addLine(containerId, text, level = 'info') {
        const body = document.getElementById(`${containerId}-body`);
        if (!body) return;

        const time = new Date().toLocaleTimeString();
        const line = document.createElement('div');
        line.className = `log-line ${level}`;
        line.dataset.level = level;
        line.innerHTML = `
            <span class="log-time">${time}</span>
            <span class="log-level">${level.toUpperCase().padEnd(5)}</span>
            <span class="log-msg">${this._escapeHtml(text)}</span>
        `;
        body.appendChild(line);

        // Auto-scroll
        const autoscroll = document.getElementById(`${containerId}-autoscroll`);
        if (autoscroll && autoscroll.checked) {
            body.scrollTop = body.scrollHeight;
        }

        // Limit lines
        while (body.children.length > 2000) {
            body.removeChild(body.firstChild);
        }
    },

    addLines(containerId, text) {
        const lines = text.split('\n');
        for (const line of lines) {
            if (!line.trim()) continue;
            let level = 'info';
            if (/\bE\/|\bERROR\b/i.test(line)) level = 'error';
            else if (/\bW\/|\bWARN/i.test(line)) level = 'warn';
            else if (/\bD\/|\bDEBUG/i.test(line)) level = 'debug';
            else if (/\bV\/|\bVERBOSE/i.test(line)) level = 'verbose';
            else if (/\bF\/|\bFATAL/i.test(line)) level = 'fatal';
            this.addLine(containerId, line, level);
        }
    },

    clear(containerId) {
        const body = document.getElementById(`${containerId}-body`);
        if (body) body.innerHTML = '';
    },

    copy(containerId) {
        const body = document.getElementById(`${containerId}-body`);
        if (!body) return;
        const text = Array.from(body.querySelectorAll('.log-msg')).map(el => el.textContent).join('\n');
        navigator.clipboard.writeText(text).then(() => Toast.success('Copied to clipboard'));
    },

    _applyFilter(containerId, level) {
        const body = document.getElementById(`${containerId}-body`);
        if (!body) return;
        const lines = body.querySelectorAll('.log-line');
        lines.forEach(line => {
            line.style.display = (level === 'all' || line.dataset.level === level) ? '' : 'none';
        });
    },

    _escapeHtml(str) {
        const div = document.createElement('div');
        div.textContent = str;
        return div.innerHTML;
    },
};
