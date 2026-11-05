(function () {
  'use strict';

  // Elements
  const authScreen = document.getElementById('auth-screen');
  const portalContainer = document.getElementById('portal-container');
  const loginForm = document.getElementById('b-login-form');
  const loginError = document.getElementById('b-login-error');
  const btnLogout = document.getElementById('btn-logout');

  const syncIndicator = document.getElementById('sync-indicator');
  const indicatorText = document.getElementById('indicator-text');
  const indicatorBadge = document.getElementById('indicator-badge');
  const btnForceSync = document.getElementById('btn-force-sync');

  const transferForm = document.getElementById('transfer-form');
  const transferSubject = document.getElementById('transfer-subject');
  const transferFile = document.getElementById('transfer-file');
  const transferStatus = document.getElementById('transfer-status');
  const btnSend = document.getElementById('btn-send');
  const outboxStat = document.getElementById('outbox-stat');

  const inboxTbody = document.getElementById('inbox-tbody');
  const inboxCount = document.getElementById('inbox-count');
  const activityLog = document.getElementById('activity-log');

  const trayHeader = document.getElementById('tray-header');
  const trayContent = document.getElementById('tray-content');
  const trayLabel = document.getElementById('tray-label');
  const trayToggleIcon = document.getElementById('tray-toggle-icon');
  const workerFrame = document.getElementById('umai-worker-frame');

  // State
  let sessionToken = sessionStorage.getItem('umai_token_b') || sessionStorage.getItem('umai_session_token_b') || '';
  let peerOrigin = '';
  let embedUrl = '';
  let umaiSession = null;
  let isAppAAuthenticated = false;

  function logActivity(msg) {
    const time = new Date().toLocaleTimeString();
    const el = document.createElement('div');
    el.innerHTML = `<span style="color: #64748b;">[${time}]</span> ${msg}`;
    activityLog.insertBefore(el, activityLog.firstChild);
    while (activityLog.children.length > 20) {
      activityLog.removeChild(activityLog.lastChild);
    }
  }

  function getAuthHeaders() {
    const headers = {};
    if (sessionToken) headers['X-UMAI-Session'] = sessionToken;
    return headers;
  }

  // Check App B authentication
  async function checkAuth() {
    try {
      const statusRes = await fetch('/api/status', { credentials: 'include' });
      const status = await statusRes.json();
      peerOrigin = status.peerOrigin;
      embedUrl = status.embedUrl || peerOrigin;

      // Ensure iframe src points to the embed URL's sync.html
      const syncUrl = new URL('/sync.html', embedUrl).toString();
      if (workerFrame.src !== syncUrl) {
        workerFrame.src = syncUrl;
      }

      const meRes = await fetch('/api/auth/me', { headers: getAuthHeaders(), credentials: 'include' });
      if (meRes.ok) {
        const me = await meRes.json();
        if (me.authenticated) {
          if (me.session_id) {
            sessionToken = me.session_id;
            sessionStorage.setItem('umai_token_b', sessionToken);
            sessionStorage.setItem('umai_session_token_b', sessionToken);
          }
          showPortal();
          return;
        }
      }
    } catch (err) {
      console.error('[Minimal B] Auth check error:', err);
    }
    showAuth();
  }

  function showAuth() {
    authScreen.style.display = 'flex';
    portalContainer.style.display = 'none';
  }

  function showPortal() {
    authScreen.style.display = 'none';
    portalContainer.style.display = 'flex';
    logActivity('Application B session established.');
    refreshInbox();
    refreshOutboxCount();
    initUmaiSession();
  }

  // Login handler
  loginForm.addEventListener('submit', async function (e) {
    e.preventDefault();
    loginError.style.display = 'none';

    try {
      const res = await fetch('/api/auth/login', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        credentials: 'include',
        body: JSON.stringify({
          username: document.getElementById('b-username').value.trim(),
          password: document.getElementById('b-password').value
        })
      });

      const data = await res.json();
      if (res.ok && (data.authenticated || data.session_id)) {
        sessionToken = data.session_id || '';
        sessionStorage.setItem('umai_token_b', sessionToken);
        sessionStorage.setItem('umai_session_token_b', sessionToken);
        showPortal();
      } else {
        loginError.textContent = data.error || 'Login failed';
        loginError.style.display = 'block';
      }
    } catch (err) {
      loginError.textContent = err.message || 'Login failed';
      loginError.style.display = 'block';
    }
  });

  // Logout handler
  btnLogout.addEventListener('click', async function () {
    try {
      await fetch('/api/auth/logout', { method: 'POST', headers: getAuthHeaders(), credentials: 'include' });
    } catch (e) {}
    sessionToken = '';
    sessionStorage.removeItem('umai_token_b');
    sessionStorage.removeItem('umai_session_token_b');
    if (umaiSession) umaiSession.stop();
    showAuth();
  });

  // UMAI Storage Adapter for App B
  const storageAdapter = {
    async getOutboxIds() {
      const res = await fetch('/api/outbox', { headers: getAuthHeaders(), credentials: 'include' });
      if (!res.ok) return [];
      const data = await res.json();
      const list = Array.isArray(data) ? data : (data.messages || []);
      return list.map(m => m.id);
    },

    async getMessage(id) {
      const res = await fetch(`/api/outbox/${encodeURIComponent(id)}`, { headers: getAuthHeaders(), credentials: 'include' });
      if (!res.ok) return null;
      const data = await res.json();
      const meta = data.message || data;
      if (!meta || !meta.id) return null;

      const files = [];
      for (const att of (meta.attachments || [])) {
        const filename = att.name || att.filename;
        const fileRes = await fetch(
          `/api/outbox/${encodeURIComponent(id)}/attachments/${encodeURIComponent(filename)}`,
          { headers: getAuthHeaders(), credentials: 'include' }
        );
        if (fileRes.ok) {
          const blob = await fileRes.blob();
          files.push(new File([blob], filename, { type: blob.type }));
        }
      }

      return { id: meta.id, payload: meta.payload || {}, attachments: files };
    },

    async isAccepted(id) {
      const res = await fetch('/api/accepted', { headers: getAuthHeaders(), credentials: 'include' });
      if (!res.ok) return false;
      const list = await res.json();
      return Array.isArray(list) && list.includes(id);
    },

    async acceptMessage(msg) {
      logActivity(`📥 Ingesting message <strong>${msg.id}</strong> (${msg.attachments.length} file(s))...`);
      const formData = new FormData();
      formData.append('id', msg.id);
      formData.append('payload', JSON.stringify(msg.payload || {}));
      for (const f of msg.attachments || []) {
        formData.append('attachments', f, f.name);
      }

      const res = await fetch('/api/inbox', {
        method: 'POST',
        headers: getAuthHeaders(),
        credentials: 'include',
        body: formData
      });

      if (res.ok) {
        logActivity(`✓ Accepted message <strong>${msg.id}</strong>. Saved to local storage.`);
        refreshInbox();
        return true;
      }
      return false;
    },

    async onAcknowledged(ids) {
      logActivity(`✓ App A acknowledged message(s): ${ids.join(', ')}. Cleaned from outbox.`);
      await fetch('/api/outbox/ack', {
        method: 'POST',
        headers: { ...getAuthHeaders(), 'Content-Type': 'application/json' },
        credentials: 'include',
        body: JSON.stringify({ ids: ids })
      });
      refreshOutboxCount();
    }
  };

  // Initialize UMAI Session
  function initUmaiSession() {
    if (umaiSession) {
      umaiSession.stop();
    }

    umaiSession = new UMAI.UmaiSession({
      peerOrigin: peerOrigin,
      role: 'host',
      iframe: workerFrame,
      storage: storageAdapter,
      onStatusChange: function ({ state, detail }) {
        updateIndicator({ state: state });
      },
      onSyncStatus: function (status) {
        updateIndicator(status);
      },
      onTransfer: function ({ direction, type, id, repeated }) {
        if (type === 'PUT' && direction === 'outgoing') {
          logActivity(`📤 Transferred message <strong>${id}</strong> via browser MessageChannel.`);
        } else if (type === 'ACK' && direction === 'outgoing') {
          logActivity(`✓ Sent ACK for message(s) to Application A${repeated ? ' (Rule 5 repeat)' : ''}.`);
        }
      }
    });

    workerFrame.addEventListener('load', function () {
      logActivity('Application A worker frame loaded. Handshaking...');
      umaiSession.start();
    });

    if (workerFrame.contentWindow) {
      umaiSession.start();
    }
  }

  // Update Real-Time Synchronization Indicator
  function updateIndicator(status = {}) {
    const state = status.state || (umaiSession ? umaiSession.state : 'disconnected');
    const isSyncing = status.isSyncing;

    syncIndicator.className = 'sync-indicator';

    if (!isAppAAuthenticated) {
      syncIndicator.classList.add('sync-auth');
      indicatorText.textContent = '🔒 App A Login Required';
      indicatorBadge.textContent = '[Click to authenticate]';
      return;
    }

    if (state !== 'connected') {
      syncIndicator.classList.add('sync-connecting');
      indicatorText.textContent = 'Connecting to App A...';
      indicatorBadge.textContent = '';
      return;
    }

    if (isSyncing) {
      syncIndicator.classList.add('sync-active');
      indicatorText.textContent = 'Syncing...';
      const detail = status.detail || 'Transfer in progress';
      indicatorBadge.textContent = detail;
    } else {
      syncIndicator.classList.add('sync-idle');
      indicatorText.textContent = '● In Sync';
      indicatorBadge.textContent = '(All up to date)';
    }
  }

  // Listen to messages from worker frame
  window.addEventListener('message', function (e) {
    if (e.data && e.data.protocol === 'UMAI_CONTROL') {
      if (e.data.type === 'AUTH_REQUIRED') {
        isAppAAuthenticated = false;
        trayContent.style.display = 'block';
        trayLabel.textContent = '🔒 Application A Authentication Required (Log in below)';
        trayToggleIcon.textContent = '▼ Collapse';
        updateIndicator();
        logActivity('⚠️ Application A requires login. Please authenticate in the bottom tray.');
      } else if (e.data.type === 'AUTH_OK') {
        isAppAAuthenticated = true;
        trayContent.style.display = 'none';
        trayLabel.textContent = '● Application A Background Node (Connected & Hidden)';
        trayToggleIcon.textContent = '▲ Expand';
        updateIndicator();
        logActivity('✓ Application A background worker authenticated.');
        if (umaiSession) umaiSession.reconcile();
      }
    }
  });

  // Tray toggle
  trayHeader.addEventListener('click', function () {
    if (trayContent.style.display === 'none') {
      trayContent.style.display = 'block';
      trayToggleIcon.textContent = '▼ Collapse';
    } else {
      trayContent.style.display = 'none';
      trayToggleIcon.textContent = '▲ Expand';
    }
  });

  // Sync indicator click triggers immediate sync
  syncIndicator.addEventListener('click', function () {
    if (!isAppAAuthenticated) {
      trayContent.style.display = 'block';
      trayToggleIcon.textContent = '▼ Collapse';
      return;
    }
    if (umaiSession) {
      logActivity('Manual reconciliation triggered.');
      umaiSession.reconcile();
      if (workerFrame && workerFrame.contentWindow) {
        workerFrame.contentWindow.postMessage({ protocol: 'UMAI_CONTROL', type: 'TRIGGER_SYNC' }, '*');
      }
    }
  });

  btnForceSync.addEventListener('click', function () {
    if (umaiSession) {
      logActivity('Manual reconciliation triggered.');
      umaiSession.reconcile();
      if (workerFrame && workerFrame.contentWindow) {
        workerFrame.contentWindow.postMessage({ protocol: 'UMAI_CONTROL', type: 'TRIGGER_SYNC' }, '*');
      }
    }
  });

  // Refresh Inbox Table
  async function refreshInbox() {
    try {
      const res = await fetch('/api/docs', { headers: getAuthHeaders(), credentials: 'include' });
      if (!res.ok) return;
      const data = await res.json();
      const docs = data.documents || [];

      inboxCount.textContent = `${docs.length} document(s)`;

      if (docs.length === 0) {
        inboxTbody.innerHTML = `
          <tr>
            <td colspan="5" class="empty-placeholder">
              No documents received from Application A yet. Upload a document in Application A to test receiving.
            </td>
          </tr>
        `;
        return;
      }

      inboxTbody.innerHTML = docs.map(doc => {
        const sizeKb = (doc.size / 1024).toFixed(1);
        const date = new Date(doc.modTime).toLocaleTimeString();
        return `
          <tr>
            <td style="font-weight: 600; color: #fff;">📄 ${escapeHtml(doc.name)}</td>
            <td style="color: var(--text-muted);">${escapeHtml(doc.name)}</td>
            <td style="color: var(--text-muted); font-family: monospace;">${sizeKb} KB</td>
            <td style="color: var(--text-muted); font-size: 12px;">${date}</td>
            <td style="text-align: right;">
              <a href="/api/docs/${encodeURIComponent(doc.name)}" download="${escapeHtml(doc.name)}" class="btn btn-secondary btn-sm" style="text-decoration:none;">
                ⬇ Download
              </a>
            </td>
          </tr>
        `;
      }).join('');
    } catch (err) {
      console.error('[Minimal B] Refresh inbox error:', err);
    }
  }

  // Refresh Outbox Count
  async function refreshOutboxCount() {
    try {
      const res = await fetch('/api/outbox', { headers: getAuthHeaders(), credentials: 'include' });
      if (!res.ok) return;
      const data = await res.json();
      const count = (data.messages || []).length;
      outboxStat.textContent = count > 0 ? `Outbox: ${count} pending transfer` : 'Outbox: 0 pending';
    } catch (err) {}
  }

  // Handle Form Submit: Send File to App A
  transferForm.addEventListener('submit', async function (e) {
    e.preventDefault();

    const file = transferFile.files[0];
    const subject = transferSubject.value.trim();
    if (!file || !subject) return;

    btnSend.disabled = true;
    transferStatus.innerHTML = '<span style="color: var(--warning);">Preparing document upload...</span>';

    try {
      // Step 1: Upload document to local App B store
      const uploadData = new FormData();
      uploadData.append('file', file);
      const uploadRes = await fetch('/api/docs', {
        method: 'POST',
        headers: getAuthHeaders(),
        credentials: 'include',
        body: uploadData
      });

      if (!uploadRes.ok) {
        throw new Error('Failed to upload file to local storage');
      }

      // Step 2: Queue message in App B's outbox
      transferStatus.innerHTML = '<span style="color: var(--warning);">Queueing UMAI message in outbox...</span>';
      const outboxRes = await fetch('/api/outbox', {
        method: 'POST',
        headers: { ...getAuthHeaders(), 'Content-Type': 'application/json' },
        credentials: 'include',
        body: JSON.stringify({
          payload: { subject: subject, timestamp: new Date().toISOString() },
          documents: [file.name]
        })
      });

      if (!outboxRes.ok) {
        throw new Error('Failed to create outbox message');
      }

      const outboxData = await outboxRes.json();
      const msgId = (outboxData && (outboxData.id || (outboxData.message && outboxData.message.id))) || 'msg';
      logActivity(`Queued message <strong>${escapeHtml(msgId)}</strong> ('${escapeHtml(subject)}') for Application A.`);

      transferForm.reset();
      refreshOutboxCount();
      transferStatus.innerHTML = '<span style="color: var(--success);">✓ Transferred & Synchronizing via UMAI!</span>';

      // Step 3: Trigger instant UMAI reconciliation
      if (umaiSession) {
        umaiSession.reconcile();
      }

      setTimeout(() => {
        transferStatus.textContent = 'Ready to send.';
      }, 4000);
    } catch (err) {
      logActivity(`❌ Error transferring document: ${err.message}`);
      transferStatus.innerHTML = `<span style="color: var(--danger);">${escapeHtml(err.message)}</span>`;
    } finally {
      btnSend.disabled = false;
    }
  });

  function escapeHtml(str) {
    return (str || '').replace(/[&<>"']/g, function (m) {
      return ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[m];
    });
  }

  // Periodic polling for inbox changes
  setInterval(refreshInbox, 3000);
  setInterval(refreshOutboxCount, 3000);

  // Start initialization
  checkAuth();
})();
