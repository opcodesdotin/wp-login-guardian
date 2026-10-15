/**
 * Login Guardian - Admin JavaScript
 * Built with Opcodes UI Micro-Engine
 *
 * @package LoginGuardian
 */

(function (window, document) {
    'use strict';

    const OpcodesUI = {
        init() {
            this.initTabs();
            this.initDialogs();
            this.initAlerts();
            this.initCopyButtons();
            this.initPasswordToggles();
            this.initTableFilters();
            this.initActivityMonitor();
        },

        initTabs() {
            const tabLists = document.querySelectorAll('.op-nav-tabs, [role="tablist"]');
            tabLists.forEach(tabList => {
                const tabs = tabList.querySelectorAll('.op-nav-tab, [role="tab"]');
                tabs.forEach((tab, index) => {
                    tab.addEventListener('click', (e) => {
                        const targetId = tab.getAttribute('data-tab-target') || tab.getAttribute('aria-controls') || tab.getAttribute('href');
                        if (!targetId || targetId === '#' || !document.querySelector(targetId)) return;
                        e.preventDefault();
                        this.activateTab(tabList, tab, targetId);
                    });

                    tab.addEventListener('keydown', (e) => {
                        let nextIndex = null;
                        if (e.key === 'ArrowRight') nextIndex = (index + 1) % tabs.length;
                        else if (e.key === 'ArrowLeft') nextIndex = (index - 1 + tabs.length) % tabs.length;

                        if (nextIndex !== null) {
                            e.preventDefault();
                            tabs[nextIndex].focus();
                            tabs[nextIndex].click();
                        }
                    });
                });
            });
        },

        activateTab(tabList, activeTab, targetPanelSelector) {
            const tabs = tabList.querySelectorAll('.op-nav-tab, [role="tab"]');
            tabs.forEach(t => {
                t.classList.remove('is-active');
                t.setAttribute('aria-selected', 'false');
            });

            activeTab.classList.add('is-active');
            activeTab.setAttribute('aria-selected', 'true');

            const container = tabList.closest('.op-wrap') || document;
            const panels = container.querySelectorAll('.op-tab-content, [role="tabpanel"]');
            panels.forEach(p => p.classList.remove('is-active'));

            const targetPanel = document.querySelector(targetPanelSelector);
            if (targetPanel) {
                targetPanel.classList.add('is-active');
            }
        },

        initDialogs() {
            document.querySelectorAll('[data-dialog-target]').forEach(trigger => {
                trigger.addEventListener('click', () => {
                    const dialogId = trigger.getAttribute('data-dialog-target');
                    const dialog = document.querySelector(dialogId);
                    if (dialog && typeof dialog.showModal === 'function') {
                        dialog.showModal();
                        dialog._triggerElement = trigger;
                    }
                });
            });

            document.querySelectorAll('[data-dialog-close]').forEach(closeBtn => {
                closeBtn.addEventListener('click', () => {
                    const dialog = closeBtn.closest('dialog');
                    if (dialog) {
                        dialog.close();
                        if (dialog._triggerElement) dialog._triggerElement.focus();
                    }
                });
            });

            document.querySelectorAll('dialog.op-dialog').forEach(dialog => {
                dialog.addEventListener('click', (e) => {
                    const rect = dialog.getBoundingClientRect();
                    const isInDialog = (
                        rect.top <= e.clientY &&
                        e.clientY <= rect.top + rect.height &&
                        rect.left <= e.clientX &&
                        e.clientX <= rect.left + rect.width
                    );
                    if (!isInDialog) dialog.close();
                });
            });
        },

        initAlerts() {
            document.querySelectorAll('.op-alert-close').forEach(btn => {
                btn.addEventListener('click', () => {
                    const alert = btn.closest('.op-alert');
                    if (alert) {
                        alert.style.transition = 'opacity 0.2s ease, transform 0.2s ease';
                        alert.style.opacity = '0';
                        alert.style.transform = 'translateY(-4px)';
                        setTimeout(() => alert.remove(), 200);
                    }
                });
            });
        },

        initCopyButtons() {
            document.querySelectorAll('[data-copy]').forEach(btn => {
                btn.addEventListener('click', async () => {
                    const textToCopy = btn.getAttribute('data-copy-text') || 
                                     (document.querySelector(btn.getAttribute('data-copy'))?.innerText ?? '');
                    if (!textToCopy) return;

                    try {
                        await navigator.clipboard.writeText(textToCopy);
                        this.toast({ message: 'Copied to clipboard!', type: 'success' });
                    } catch (err) {
                        this.toast({ message: 'Failed to copy', type: 'danger' });
                    }
                });
            });
        },

        initPasswordToggles() {
            document.querySelectorAll('[data-toggle-password]').forEach(toggle => {
                toggle.addEventListener('click', () => {
                    const targetSelector = toggle.getAttribute('data-toggle-password');
                    const input = document.querySelector(targetSelector);
                    if (!input) return;

                    const isPassword = input.type === 'password';
                    input.type = isPassword ? 'text' : 'password';
                    toggle.setAttribute('aria-pressed', isPassword ? 'true' : 'false');
                });
            });
        },

        initTableFilters() {
            document.querySelectorAll('[data-table-search]').forEach(input => {
                const tableSelector = input.getAttribute('data-table-search');
                const table = document.querySelector(tableSelector);
                if (!table) return;

                input.addEventListener('input', () => {
                    const query = input.value.toLowerCase().trim();
                    const rows = table.querySelectorAll('tbody tr');
                    rows.forEach(row => {
                        const text = row.innerText.toLowerCase();
                        row.style.display = text.includes(query) ? '' : 'none';
                    });
                });
            });
        },

        toast({ message, type = 'info', duration = 3500 }) {
            let container = document.querySelector('.op-toast-container');
            if (!container) {
                container = document.createElement('div');
                container.className = 'op-toast-container';
                container.setAttribute('aria-live', 'polite');
                document.body.appendChild(container);
            }

            const toast = document.createElement('div');
            toast.className = `op-toast op-toast-${type}`;

            let iconSvg = '';
            if (type === 'success') {
                iconSvg = '<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><polyline points="20 6 9 17 4 12"></polyline></svg>';
            } else if (type === 'danger') {
                iconSvg = '<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><circle cx="12" cy="12" r="10"></circle><line x1="15" y1="9" x2="9" y2="15"></line><line x1="9" y1="9" x2="15" y2="15"></line></svg>';
            } else {
                iconSvg = '<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><circle cx="12" cy="12" r="10"></circle><line x1="12" y1="16" x2="12" y2="12"></line><line x1="12" y1="8" x2="12.01" y2="8"></line></svg>';
            }

            toast.innerHTML = `
                <span class="op-toast-icon" style="display:flex;align-items:center;">${iconSvg}</span>
                <span style="flex:1;">${message}</span>
            `;

            container.appendChild(toast);

            setTimeout(() => {
                toast.style.transition = 'opacity 0.25s ease, transform 0.25s ease';
                toast.style.opacity = '0';
                toast.style.transform = 'translateY(8px)';
                setTimeout(() => toast.remove(), 250);
            }, duration);
        },

        /**
         * Activity Monitor AJAX Controller
         */
        initActivityMonitor() {
            const table = document.getElementById('alg-table');
            if (!table) return;

            const escapeHtml = (text) => {
                const div = document.createElement('div');
                div.textContent = text || '';
                return div.innerHTML;
            };

            const ajax = (action, data) => new Promise((resolve, reject) => {
                const fd = new FormData();
                fd.append('action', action);
                Object.entries(data || {}).forEach(([k, v]) => fd.append(k, v));
                fetch(ajaxurl, { method: 'POST', credentials: 'same-origin', body: fd })
                    .then(r => r.json())
                    .then(j => { if (j.success) resolve(j.data); else reject(j.data || j); })
                    .catch(reject);
            });

            const state = { page: 1, per: 25, s: '', status: '' };

            const render = (data) => {
                const rows = data.rows || [];
                let html = '<div class="op-table-responsive"><table class="op-table op-table-striped"><thead><tr>' +
                    '<th>ID</th><th>Timestamp (UTC)</th><th>User Target</th><th>User ID</th><th>Origin IP</th><th>Status</th><th>User Agent</th><th>Reason</th><th style="text-align:end;">Action</th>' +
                    '</tr></thead><tbody>';

                if (!rows.length) {
                    html += '<tr><td colspan="9" style="text-align:center;padding:24px;color:var(--op-text-muted);">No activity records found matching criteria.</td></tr>';
                }

                rows.forEach(r => {
                    let badgeClass = 'op-badge-neutral';
                    if (r.status === 'success') badgeClass = 'op-badge-success';
                    else if (r.status === 'lockout' || r.status === 'blocked') badgeClass = 'op-badge-danger';
                    else if (r.status === 'failed') badgeClass = 'op-badge-warning';

                    html += '<tr>' +
                        `<td><code>#${escapeHtml(r.id)}</code></td>` +
                        `<td><strong>${escapeHtml(r.event_time)}</strong></td>` +
                        `<td>${escapeHtml(r.user_login || '—')}</td>` +
                        `<td>${escapeHtml(r.user_id || '—')}</td>` +
                        `<td><code>${escapeHtml(r.ip)}</code></td>` +
                        `<td><span class="op-badge ${badgeClass}"><span class="op-badge-dot"></span> ${escapeHtml(r.status)}</span></td>` +
                        `<td style="max-width:180px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;" title="${escapeHtml(r.ua || '')}">${escapeHtml(r.ua || '—')}</td>` +
                        `<td>${escapeHtml(r.reason || '—')}</td>` +
                        `<td style="text-align:end;"><button type="button" class="op-btn op-btn-ghost op-btn-sm alg-report-btn" data-ip="${escapeHtml(r.ip)}">Report IP</button></td>` +
                        '</tr>';
                });

                html += '</tbody></table></div>';

                const total = data.total || 0;
                const pages = Math.max(1, Math.ceil(total / state.per));
                html += `<div class="op-panel-footer">` +
                    `<div style="font-size:var(--op-font-sm);color:var(--op-text-muted);">Page <strong>${state.page}</strong> of <strong>${pages}</strong> &bull; Total ${total} entries</div>` +
                    `<div style="display:flex;gap:6px;">` +
                    `<button type="button" class="op-btn op-btn-secondary op-btn-sm" id="alg-prev" ${state.page <= 1 ? 'disabled' : ''}>Previous</button>` +
                    `<button type="button" class="op-btn op-btn-secondary op-btn-sm" id="alg-next" ${state.page >= pages ? 'disabled' : ''}>Next</button>` +
                    `</div>` +
                    `</div>`;

                table.innerHTML = html;

                document.getElementById('alg-prev')?.addEventListener('click', () => { if (state.page > 1) { state.page--; load(); } });
                document.getElementById('alg-next')?.addEventListener('click', () => { state.page++; load(); });

                table.querySelectorAll('.alg-report-btn').forEach(btn => {
                    btn.addEventListener('click', e => {
                        const ip = e.target.dataset.ip;
                        if (!ip) return;
                        btn.disabled = true;
                        btn.textContent = 'Reporting...';
                        const reportNonce = document.getElementById('alg-refresh')?.dataset?.nonce || '';
                        ajax('alg_report_ip', { _ajax_nonce: reportNonce, ip })
                            .then(res => {
                                let msgs = [];
                                if (res.abuseipdb) msgs.push('AbuseIPDB: ' + (res.abuseipdb.message || (res.abuseipdb.success ? 'Success' : 'Failed')));
                                if (res.spamhaus) msgs.push('Spamhaus: ' + (res.spamhaus.message || (res.spamhaus.success ? 'Success' : 'Failed')));
                                if (!msgs.length) msgs.push('No reporting APIs enabled or IP was reported recently.');
                                OpcodesUI.toast({ message: msgs.join('; '), type: 'info' });
                            })
                            .catch(err => {
                                OpcodesUI.toast({ message: 'Report failed: ' + (err?.message || 'Error'), type: 'danger' });
                            })
                            .finally(() => {
                                btn.disabled = false;
                                btn.textContent = 'Report IP';
                            });
                    });
                });
            };

            const load = () => {
                const refreshBtn = document.getElementById('alg-refresh');
                if (!refreshBtn) return;
                ajax('alg_fetch_logs', {
                    _ajax_nonce: refreshBtn.dataset.nonce,
                    page: state.page,
                    per: state.per,
                    s: state.s,
                    status: state.status
                })
                .then(render)
                .catch(e => {
                    table.innerHTML = '<div class="op-alert op-alert-danger"><div class="op-alert-content"><div class="op-alert-title">Failed to load logs</div><div>' + (e?.toString?.() || 'Error') + '</div></div></div>';
                });
            };

            document.getElementById('alg-refresh')?.addEventListener('click', () => {
                load();
                OpcodesUI.toast({ message: 'Activity logs refreshed', type: 'info' });
            });

            document.getElementById('alg-search')?.addEventListener('input', e => {
                state.s = e.target.value;
                state.page = 1;
                load();
            });

            document.getElementById('alg-status')?.addEventListener('change', e => {
                state.status = e.target.value;
                state.page = 1;
                load();
            });

            document.getElementById('alg-export')?.addEventListener('click', () => {
                const refreshBtn = document.getElementById('alg-refresh');
                if (!refreshBtn) return;
                OpcodesUI.toast({ message: 'Generating CSV export...', type: 'info' });
                ajax('alg_fetch_logs', {
                    _ajax_nonce: refreshBtn.dataset.nonce,
                    page: state.page,
                    per: state.per,
                    s: state.s,
                    status: state.status,
                    export: 1
                })
                .then(data => {
                    const a = document.createElement('a');
                    a.href = 'data:text/csv;base64,' + data.csv;
                    a.download = data.filename;
                    a.click();
                    OpcodesUI.toast({ message: 'CSV export downloaded', type: 'success' });
                });
            });

            document.getElementById('alg-purge')?.addEventListener('click', () => {
                const purgeBtn = document.getElementById('alg-purge');
                if (!purgeBtn) return;
                ajax('alg_purge_logs', { _ajax_nonce: purgeBtn.dataset.nonce })
                    .then(() => {
                        load();
                        OpcodesUI.toast({ message: 'Old logs purged successfully', type: 'success' });
                    });
            });

            // Initial load
            load();
        }
    };

    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', () => OpcodesUI.init());
    } else {
        OpcodesUI.init();
    }

    window.OpcodesUI = OpcodesUI;
})(window, document);
