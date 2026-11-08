(function () {
  'use strict';

  if ('serviceWorker' in navigator) {
    navigator.serviceWorker.getRegistrations().then(function (regs) {
      for (const r of regs) r.unregister();
    });
  }

  // Elements
  const authScreen = document.getElementById('auth-screen');
  const portalContainer = document.getElementById('portal-container');
  const loginForm = document.getElementById('b-login-form');
  const loginError = document.getElementById('b-login-error');
  const btnLogout = document.getElementById('btn-logout');

  const syncIndicator = document.getElementById('sync-indicator');
  const indicatorText = document.getElementById('indicator-text');
  const indicatorBadge = document.getElementById('indicator-badge');

  const transferForm = document.getElementById('transfer-form');
  const transferSubject = document.getElementById('transfer-subject');
  const transferFile = document.getElementById('transfer-file');
  const transferStatus = document.getElementById('transfer-status');
  const btnSend = document.getElementById('btn-send');
  const outboxStat = document.getElementById('outbox-stat');

  const inboxTbody = document.getElementById('inbox-tbody');
  const inboxCount = document.getElementById('inbox-count');

  const trayHeader = document.getElementById('tray-header');
  const trayContent = document.getElementById('tray-content');
  const trayLabel = document.getElementById('tray-label');
  const trayToggleIcon = document.getElementById('tray-toggle-icon');
  const workerFrame = document.getElementById('umai-worker-frame');

  // State
  let isAuthenticated = false;
  let peerOrigin = '';
  let embedUrl = '';
  let syncUrl = '';
  let umaiSession = null;
  let isAppAAuthenticated = false;
  let workerSyncStatus = null;

  async function api(path, options = {}) {
    options.credentials = 'include';
    options.headers = options.headers || {};
    options.headers['X-UMAI-CSRF'] = '1';
    const res = await fetch(path, options);
    if (res.status === 401) {
      isAuthenticated = false;
      showAuth();
      throw new Error('Unauthorized');
    }
    return res;
  }

  // Check App B authentication
  async function checkAuth() {
    try {
      const statusRes = await fetch('/api/status', { credentials: 'include' });
      const status = await statusRes.json();
      peerOrigin = status.peer_origin || status.peerOrigin || 'http://127.0.0.1:8081';
      embedUrl = status.peer_embed_url || status.peerEmbedURL || peerOrigin;

      if (window.location.hostname === 'localhost') {
        peerOrigin = peerOrigin.replace('127.0.0.1', 'localhost');
        embedUrl = embedUrl.replace('127.0.0.1', 'localhost');
      } else if (window.location.hostname === '127.0.0.1') {
        peerOrigin = peerOrigin.replace('localhost', '127.0.0.1');
        embedUrl = embedUrl.replace('localhost', '127.0.0.1');
      }

      let syncBase = peerOrigin;
      try {
        syncBase = new URL(embedUrl).origin;
      } catch (e) {}
      syncUrl = new URL('/sync.html', syncBase).toString();

      const meRes = await api('/api/auth/me');
      if (meRes.ok) {
        const me = await meRes.json();
        if (me.authenticated) {
          isAuthenticated = true;
          showPortal();
          return;
        }
      }
    } catch (err) {
      // 401 or error falls through to showAuth
    }
    isAuthenticated = false;
    showAuth();
  }

  function showAuth() {
    if (umaiSession) {
      umaiSession.stop();
      umaiSession = null;
    }
    authScreen.style.display = 'flex';
    portalContainer.style.display = 'none';
  }

  function showPortal() {
    authScreen.style.display = 'none';
    portalContainer.style.display = 'flex';
    refreshInbox();
    refreshOutboxCount();
    initUmaiSession();

    // Load or reload the background worker iframe after host session is ready
    if (syncUrl && workerFrame.src !== syncUrl) {
      workerFrame.src = syncUrl;
    } else if (workerFrame.contentWindow && peerOrigin) {
      workerFrame.contentWindow.postMessage({ protocol: 'UMAI_CONTROL', type: 'PING_AUTH' }, peerOrigin);
    }
  }

  // Login handler
  loginForm.addEventListener('submit', async function (e) {
    e.preventDefault();
    loginError.style.display = 'none';

    try {
      const res = await fetch('/api/auth/login', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'X-UMAI-CSRF': '1' },
        credentials: 'include',
        body: JSON.stringify({
          username: document.getElementById('b-username').value.trim(),
          password: document.getElementById('b-password').value
        })
      });

      const data = await res.json();
      if (res.ok && data.authenticated) {
        isAuthenticated = true;
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
      await api('/api/auth/logout', { method: 'POST' });
    } catch (e) {}
    isAuthenticated = false;
    showAuth();
  });

  // UMAI Storage Adapter for App B
  const storageAdapter = {
    async getOutboxIds() {
      const res = await api('/api/outbox');
      if (!res.ok) return [];
      const data = await res.json();
      const list = Array.isArray(data) ? data : (data.messages || []);
      return list.map(m => m.id);
    },

    async getMessage(id) {
      const res = await api(`/api/outbox/${encodeURIComponent(id)}`);
      if (!res.ok) return null;
      const data = await res.json();
      const meta = data.message || data;
      if (!meta || !meta.id) return null;

      const files = [];
      for (const att of (meta.attachments || [])) {
        const filename = att.name || att.filename;
        const fileRes = await api(
          `/api/outbox/${encodeURIComponent(id)}/attachments/${encodeURIComponent(filename)}`
        );
        if (fileRes.ok) {
          const blob = await fileRes.blob();
          files.push(new File([blob], filename, { type: blob.type }));
        }
      }

      return {
        id: meta.id,
        payload: (meta.payload !== undefined && meta.payload !== null) ? meta.payload : {},
        attachments: files,
        signature: meta.signature || ''
      };
    },

    async isAccepted(id) {
      const res = await api('/api/accepted/receipts');
      if (!res.ok) return { accepted: false };
      const receiptsMap = await res.json();
      if (receiptsMap && Object.prototype.hasOwnProperty.call(receiptsMap, id)) {
        return { accepted: true, ackReceipt: receiptsMap[id] || '' };
      }
      return { accepted: false };
    },

    async acceptMessage(msg) {
      const formData = new FormData();
      formData.append('id', msg.id);
      const safePayload = (msg.payload !== undefined && msg.payload !== null) ? msg.payload : {};
      formData.append('payload', JSON.stringify(safePayload));
      if (msg.signature) {
        formData.append('signature', msg.signature);
      }
      for (const f of msg.attachments || []) {
        formData.append('attachments', f, f.name);
      }

      const res = await api('/api/inbox', {
        method: 'POST',
        body: formData
      });

      if (res.ok) {
        const data = await res.json();
        refreshInbox();
        return { accepted: true, ackReceipt: data.ack_receipt || '' };
      }
      return { accepted: false };
    },

    async onAcknowledged(ids, receipts) {
      const res = await api('/api/outbox/ack', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ ids: ids, receipts: receipts || {} })
      });
      if (!res.ok) {
        throw new Error('Failed to acknowledge outbox messages on server');
      }
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
      onStatusChange: function ({ state }) {
        updateIndicator();
      },
      onSyncStatus: function () {
        updateIndicator();
      }
    });

    if (!workerFrame._loadBound) {
      workerFrame._loadBound = true;
      workerFrame.addEventListener('load', function () {
        if (workerFrame.src && workerFrame.src !== 'about:blank') {
          if (workerFrame.contentWindow && peerOrigin) {
            workerFrame.contentWindow.postMessage({ protocol: 'UMAI_CONTROL', type: 'PING_AUTH' }, peerOrigin);
          }
          if (umaiSession) {
            umaiSession.start();
          }
        }
      });
    }

    umaiSession.start();
  }

  // Update Real-Time Synchronization Indicator
  function updateIndicator() {
    const hostStatus = umaiSession ? umaiSession.getSyncStatus() : { state: 'disconnected', isSyncing: false };
    const state = hostStatus.state;
    const isSyncing = hostStatus.isSyncing || (workerSyncStatus && workerSyncStatus.isSyncing);

    syncIndicator.className = 'sync-indicator';

    if (!isAppAAuthenticated) {
      syncIndicator.classList.add('sync-auth');
      indicatorText.textContent = '🔒 App A Login Required';
      indicatorBadge.textContent = '';
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
      indicatorBadge.textContent = '';
    } else {
      syncIndicator.classList.add('sync-idle');
      indicatorText.textContent = 'In Sync';
      indicatorBadge.textContent = '';
    }
  }

  // Listen to messages from worker frame
  window.addEventListener('message', function (e) {
    if (peerOrigin && e.origin !== peerOrigin) return;
    if (workerFrame && workerFrame.contentWindow && e.source !== workerFrame.contentWindow) return;
    if (!e.data || e.data.protocol !== 'UMAI_CONTROL') return;

    if (e.data.type === 'AUTH_REQUIRED') {
      isAppAAuthenticated = false;
      trayContent.style.display = 'block';
      trayLabel.textContent = '🔒 Application A Login Required (Sign in below)';
      trayToggleIcon.textContent = '▼ Collapse';
      updateIndicator();
    } else if (e.data.type === 'AUTH_OK') {
      isAppAAuthenticated = true;
      trayContent.style.display = 'none';
      trayLabel.textContent = '● Application A Sync Worker (Connected)';
      trayToggleIcon.textContent = '▲ Expand';
      updateIndicator();
      if (umaiSession) {
        if (umaiSession.state !== 'connected') {
          umaiSession.start();
        } else {
          umaiSession.reconcile();
        }
      }
    } else if (e.data.type === 'SYNC_STATUS') {
      workerSyncStatus = e.data.status || null;
      updateIndicator();
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

  // Sync indicator click triggers immediate sync or opens auth tray
  syncIndicator.addEventListener('click', function () {
    if (!isAppAAuthenticated) {
      trayContent.style.display = 'block';
      trayToggleIcon.textContent = '▼ Collapse';
      return;
    }
    if (umaiSession) {
      umaiSession.reconcile();
      if (workerFrame && workerFrame.contentWindow && peerOrigin) {
        workerFrame.contentWindow.postMessage({ protocol: 'UMAI_CONTROL', type: 'TRIGGER_SYNC' }, peerOrigin);
      }
    }
  });

  // Refresh Inbox Table (Messages received from Application A)
  async function refreshInbox() {
    if (!isAuthenticated) return;
    try {
      const res = await api('/api/inbox');
      if (!res.ok) return;
      const data = await res.json();
      const messages = Array.isArray(data) ? data : (data.messages || []);

      inboxCount.textContent = `${messages.length} message${messages.length === 1 ? '' : 's'}`;

      if (messages.length === 0) {
        inboxTbody.innerHTML = `
          <tr>
            <td colspan="4" class="empty-placeholder">
              No messages received from Application A yet.
            </td>
          </tr>
        `;
        return;
      }

      const rows = messages.map(msg => {
        const subj = (msg.payload && msg.payload.subject) || 'No subject';
        const note = (msg.payload && msg.payload.text) ? ` — ${msg.payload.text}` : '';
        const date = new Date(msg.created_at || Date.now()).toLocaleTimeString();
        const attachments = msg.attachments || [];

        const attDisplay = attachments.length === 0
          ? '<span style="color: var(--text-muted);">—</span>'
          : attachments.map(a => `${escapeHtml(a.name)} (${formatBytes(a.size)})`).join(', ');

        return `
          <tr>
            <td style="font-family: monospace; font-size: 12px; color: var(--text-muted);">${escapeHtml(msg.id)}</td>
            <td style="font-weight: 500; color: #fff;">${escapeHtml(subj)}<span style="color: var(--text-muted); font-weight: normal;">${escapeHtml(note)}</span></td>
            <td style="color: var(--text-muted); font-size: 12px;">${attDisplay}</td>
            <td style="text-align: right; color: var(--text-muted); font-size: 12px;">${date}</td>
          </tr>
        `;
      });

      inboxTbody.innerHTML = rows.join('');
    } catch (err) {}
  }

  // Refresh Outbox Count
  async function refreshOutboxCount() {
    if (!isAuthenticated) return;
    try {
      const res = await api('/api/outbox');
      if (!res.ok) return;
      const data = await res.json();
      const count = (Array.isArray(data) ? data : (data.messages || [])).length;
      outboxStat.textContent = `Outbox: ${count} pending`;
    } catch (err) {}
  }

  // Handle Form Submit: Send Message to App A (with optional attachment)
  transferForm.addEventListener('submit', async function (e) {
    e.preventDefault();

    const file = transferFile.files[0] || null;
    const subject = transferSubject.value.trim();
    if (!subject) return;

    btnSend.disabled = true;
    transferStatus.innerHTML = '<span style="color: var(--warning);">Sending...</span>';

    try {
      const docNames = [];

      // If an attachment is selected, upload it to App B's document store first
      if (file) {
        const uploadData = new FormData();
        uploadData.append('file', file);
        const uploadRes = await api('/api/docs', {
          method: 'POST',
          body: uploadData
        });
        if (!uploadRes.ok) {
          throw new Error('Failed to stage attachment');
        }
        docNames.push(file.name);
      }

      // Create message in App B's outbox
      const outboxRes = await api('/api/outbox', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          payload: { subject: subject, timestamp: new Date().toISOString() },
          documents: docNames
        })
      });

      if (!outboxRes.ok) {
        throw new Error('Failed to create message');
      }

      transferForm.reset();
      refreshOutboxCount();
      transferStatus.innerHTML = '<span style="color: var(--success);">✓ Queued for synchronization</span>';

      if (umaiSession) {
        umaiSession.reconcile();
      }

      setTimeout(() => {
        transferStatus.textContent = '';
      }, 3000);
    } catch (err) {
      transferStatus.innerHTML = `<span style="color: var(--danger);">${escapeHtml(err.message)}</span>`;
    } finally {
      btnSend.disabled = false;
    }
  });

  function formatBytes(bytes) {
    if (!bytes || bytes === 0) return '0 B';
    const k = 1024;
    const sizes = ['B', 'KB', 'MB', 'GB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(1)) + ' ' + sizes[i];
  }

  function escapeHtml(str) {
    return String(str || '').replace(/[&<>"']/g, function (m) {
      return ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[m];
    });
  }

  // Periodic polling for inbox and outbox changes
  setInterval(() => {
    if (isAuthenticated) {
      refreshInbox();
      refreshOutboxCount();
    }
  }, 2000);

  // Start initialization
  checkAuth();
})();
