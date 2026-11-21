/**
 * ASAT — Modal Component
 */
const Modal = {
    show(title, bodyHtml, options = {}) {
        const container = document.getElementById('modal-container');
        const id = 'modal-' + Date.now();

        const footerHtml = options.footer || `
            ${options.cancelText ? `<button class="btn" onclick="Modal.close('${id}')">${options.cancelText}</button>` : ''}
            ${options.confirmText ? `<button class="btn btn-primary" id="${id}-confirm">${options.confirmText}</button>` : ''}
        `;

        container.innerHTML = `
            <div class="modal-overlay" id="${id}" onclick="if(event.target===this)Modal.close('${id}')">
                <div class="modal" style="max-width:${options.width || '550px'}">
                    <div class="modal-header">
                        <h3 class="modal-title">${title}</h3>
                        <button class="modal-close" onclick="Modal.close('${id}')">&times;</button>
                    </div>
                    <div class="modal-body">${bodyHtml}</div>
                    ${footerHtml ? `<div class="modal-footer">${footerHtml}</div>` : ''}
                </div>
            </div>
        `;

        if (options.onConfirm) {
            const btn = document.getElementById(`${id}-confirm`);
            if (btn) btn.addEventListener('click', () => { options.onConfirm(); Modal.close(id); });
        }

        return id;
    },

    close(id) {
        const el = document.getElementById(id);
        if (el) el.remove();
    },

    confirm(title, message, onConfirm) {
        return this.show(title, `<p style="color:var(--text-secondary)">${message}</p>`, {
            confirmText: 'Confirm',
            cancelText: 'Cancel',
            onConfirm,
        });
    },
};
