/**
 * ASAT — Chart Helpers
 * Wrapper around Chart.js for consistent styling.
 */
const Charts = {
    _instances: {},

    defaults: {
        color: '#94a3b8',
        borderColor: 'rgba(100, 120, 255, 0.08)',
        font: { family: "'Inter', sans-serif", size: 11 },
    },

    _applyDefaults() {
        if (typeof Chart === 'undefined') return;
        Chart.defaults.color = this.defaults.color;
        Chart.defaults.borderColor = this.defaults.borderColor;
        Chart.defaults.font.family = this.defaults.font.family;
        Chart.defaults.font.size = this.defaults.font.size;
    },

    destroy(canvasId) {
        if (this._instances[canvasId]) {
            this._instances[canvasId].destroy();
            delete this._instances[canvasId];
        }
    },

    donut(canvasId, labels, data, colors) {
        this._applyDefaults();
        this.destroy(canvasId);
        const ctx = document.getElementById(canvasId);
        if (!ctx) return;

        this._instances[canvasId] = new Chart(ctx, {
            type: 'doughnut',
            data: {
                labels,
                datasets: [{
                    data,
                    backgroundColor: colors || ['#ef4444', '#f97316', '#eab308', '#22c55e', '#3b82f6'],
                    borderWidth: 0,
                    hoverOffset: 6,
                }],
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                cutout: '72%',
                plugins: {
                    legend: { position: 'bottom', labels: { padding: 15, usePointStyle: true, pointStyleWidth: 8 } },
                },
            },
        });
    },

    bar(canvasId, labels, datasets) {
        this._applyDefaults();
        this.destroy(canvasId);
        const ctx = document.getElementById(canvasId);
        if (!ctx) return;

        this._instances[canvasId] = new Chart(ctx, {
            type: 'bar',
            data: { labels, datasets },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: { legend: { display: datasets.length > 1 } },
                scales: {
                    x: { grid: { display: false } },
                    y: { beginAtZero: true, grid: { color: 'rgba(100,120,255,0.05)' } },
                },
            },
        });
    },

    line(canvasId, labels, datasets) {
        this._applyDefaults();
        this.destroy(canvasId);
        const ctx = document.getElementById(canvasId);
        if (!ctx) return;

        this._instances[canvasId] = new Chart(ctx, {
            type: 'line',
            data: { labels, datasets: datasets.map(ds => ({
                ...ds,
                tension: 0.4,
                fill: true,
                pointRadius: 3,
                pointHoverRadius: 6,
            }))},
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: { legend: { display: datasets.length > 1 } },
                scales: {
                    x: { grid: { display: false } },
                    y: { beginAtZero: true, grid: { color: 'rgba(100,120,255,0.05)' } },
                },
            },
        });
    },
};
