/**
 * ASAT — Reports Page
 */
const ReportsPage = {
    async render() {
        const content = document.getElementById('page-content');
        content.innerHTML = `
            <div class="animate-fadeIn">
                <div class="page-header">
                    <div><h1>Reports</h1><p class="page-description">Generate, view, and download security assessment reports</p></div>
                    <div class="page-actions">
                        <button class="btn btn-primary" onclick="ReportsPage.showGenerateModal()">📄 Generate Report</button>
                    </div>
                </div>
                <div id="reports-list">
                    <div class="flex items-center justify-content gap-2"><div class="spinner"></div></div>
                </div>
            </div>
        `;
        this.loadReports();
    },

    async loadReports() {
        try {
            const data = await API.get('/api/v1/reports/');
            const container = document.getElementById('reports-list');

            if (!data.reports || data.reports.length === 0) {
                container.innerHTML = `
                    <div class="empty-state">
                        <div class="empty-icon">📄</div>
                        <div class="empty-title">No Reports Yet</div>
                        <div class="empty-text">Run some scans, then generate a security assessment report.</div>
                        <button class="btn btn-primary" onclick="ReportsPage.showGenerateModal()">Generate Report</button>
                    </div>`;
                return;
            }

            container.innerHTML = `<div class="table-container"><table class="data-table">
                <thead><tr><th>Title</th><th>Format</th><th>Size</th><th>Created</th><th>Actions</th></tr></thead>
                <tbody>${data.reports.map(r => `
                    <tr>
                        <td class="fw-medium">${r.title}</td>
                        <td><span class="badge badge-info">${r.report_format.toUpperCase()}</span></td>
                        <td class="text-muted">${r.file_size ? (r.file_size / 1024).toFixed(1) + ' KB' : '—'}</td>
                        <td class="text-muted">${new Date(r.created_at).toLocaleString()}</td>
                        <td class="flex gap-2">
                            <button class="btn btn-sm" onclick="ReportsPage.download(${r.id}, '${r.title}.${r.report_format}')">⬇️ Download</button>
                            <button class="btn btn-sm btn-danger" onclick="ReportsPage.deleteReport(${r.id})">🗑️</button>
                        </td>
                    </tr>
                `).join('')}</tbody>
            </table></div>`;
        } catch (e) { Toast.error(e.message); }
    },

    showGenerateModal() {
        Modal.show('📄 Generate Report', `
            <form id="gen-report-form" class="flex flex-col gap-4">
                <div class="form-group">
                    <label class="form-label">Report Title</label>
                    <input class="form-input" id="report-title" value="Security Assessment Report" required>
                </div>
                <div class="form-group">
                    <label class="form-label">Description</label>
                    <input class="form-input" id="report-desc" placeholder="Optional description">
                </div>
                <div class="form-group">
                    <label class="form-label">Format</label>
                    <select class="form-select" id="report-format">
                        <option value="pdf">📄 PDF</option>
                        <option value="html">🌐 HTML</option>
                        <option value="csv">📊 CSV</option>
                    </select>
                </div>
                <div class="form-group">
                    <label class="form-label">Scan IDs (comma-separated)</label>
                    <input class="form-input" id="report-scans" placeholder="e.g., 1,2,3" required>
                    <span class="text-muted" style="font-size:var(--fs-xs)">Enter the IDs of scan results to include in this report</span>
                </div>
            </form>
        `, {
            confirmText: 'Generate',
            cancelText: 'Cancel',
            onConfirm: () => this.generate(),
        });
    },

    async generate() {
        const title = document.getElementById('report-title').value;
        const description = document.getElementById('report-desc').value;
        const format = document.getElementById('report-format').value;
        const scans = document.getElementById('report-scans').value;

        const scanIds = scans.split(',').map(s => parseInt(s.trim())).filter(n => !isNaN(n));
        if (!scanIds.length) return Toast.warning('Enter at least one scan ID');

        try {
            Toast.info('Generating report...');
            await API.post('/api/v1/reports/generate', {
                title, description, report_format: format, scan_ids: scanIds,
            });
            Toast.success('Report generated!');
            this.loadReports();
        } catch (e) { Toast.error(e.message); }
    },

    async download(id, filename) {
        try {
            await API.download(`/api/v1/reports/${id}/download`, filename);
            Toast.success('Download started');
        } catch (e) { Toast.error(e.message); }
    },

    async deleteReport(id) {
        Modal.confirm('Delete Report', 'This will permanently delete this report.', async () => {
            try {
                await API.delete(`/api/v1/reports/${id}`);
                Toast.success('Report deleted');
                this.loadReports();
            } catch (e) { Toast.error(e.message); }
        });
    },
};
